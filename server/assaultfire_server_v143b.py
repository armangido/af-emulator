# v139 coverage policy:
# CURRENT_BRANCH  = active handler in this file.
# CURRENT_PARTIAL = active handler but schema/lifecycle still under live validation.
# PRIOR_RECOVERED = numeric ID recovered in the older broad backend; not silently
#                   copied into this specialized PVE branch.
# MAPPED_ONLY     = numeric ID known, active handler absent.
# UNRESOLVED      = present in UTGame.u catalog, numeric ID deliberately not guessed.
#
import re
from pathlib import Path
import socket
import threading
import time
import struct

import hashlib
import os
import subprocess
import csv
import io
import json
import sys
from collections.abc import MutableMapping, MutableSequence

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from assaultfire_ds_spawner import (
    AFDEV_MODE_IDS,
    DedicatedServerSpawner,
    DSCapacityError,
    DSStartupError,
    SpawnerConfig,
    SpawnerError,
)

from assaultfire_room_registry import (
    RoomRegistry,
    RoomRegistryError,
)

from assaultfire_preflight import (
    default_preflight_status_path,
    run_server_preflight,
    update_launch_gate_status,
)
from assaultfire_database_logging import build_logger
from assaultfire_auth import parse_client_dh_plaintext
from assaultfire_boot import resolve_private_key_path, server_only_requested
from player_db import DEFAULT_DB_PATH as PLAYER_DB_PATH, PlayerDatabase, PlayerDBError
from friends_service import (
    A310_WIRE_RECOVERY,
    EPTE_ADD_BY_ALL,
    SNS_ERR_SUCC,
    FriendsError,
    FriendsService,
    build_add_friend_result,
    build_chat_p2p_notify,
    build_delete_friend_response,
    build_friend_invite,
    build_friend_status_response,
    build_query_friend_response,
    parse_add_friend_client_response,
    parse_add_friend_request,
    parse_chat_p2p_request,
    parse_delete_friend_request,
    parse_friend_status_request,
    parse_query_friend_request,
    build_friend_loginout,
    build_player_exp_response,
    parse_player_exp_request,
    parse_read_offline_message_notice,
)
from clan_db import ClanDatabase
from clan_service import ClanService, COMMANDS as CLAN_COMMANDS, SENSITIVE_COMMANDS as CLAN_SENSITIVE_COMMANDS
from development_web import (
    DevelopmentWebError,
    DevelopmentWebProcess,
    resolve_runtime_mode,
    development_web_requested,
)
from assaultfire_ap_auth import (
    authenticate_ap_verify_body,
    build_ap_result_plaintext,
)

# Hosted reconnect persistence: keep sessions alive long enough for rolling
# updates/restarts. Operators can still override this in the environment.
os.environ.setdefault("AF_TGAME_SESSION_TTL_SECONDS", "3600")

from tgame_ticket_state import (
    SESSION_TTL_SECONDS,
    get_unexpired_session_uins,
    get_sessions_for_ip,
    get_ticket_crypto,
    issue_ticket,
    save_transport_key,
    touch_session,
)
from tgame_reconnect import parse_cmd06_resume

try:
    TGAME_SESSION_TOUCH_INTERVAL_SECONDS = max(
        15.0,
        min(300.0, float(os.environ.get("AF_TGAME_SESSION_TOUCH_SECONDS", "60"))),
    )
except (TypeError, ValueError):
    TGAME_SESSION_TOUCH_INTERVAL_SECONDS = 60.0

# v24: v20 success framing plus BOTH PublicData bitmap and PrivateData tail probes.
QUIET_ROLE_HEX = True
DEBUG_AUTH_HEX = os.environ.get("AF_DEBUG_AUTH_HEX", "").strip().lower() in (
    "1", "true", "yes", "on"
)
SERVER_ONLY_MODE = server_only_requested(sys.argv[1:], os.environ)
try:
    RUNTIME_MODE = resolve_runtime_mode(sys.argv[1:], os.environ)
except DevelopmentWebError as _runtime_mode_error:
    print(f"[BOOT] invalid runtime mode: {_runtime_mode_error}", flush=True)
    raise SystemExit(2)

DEV_WEB_ENABLED = development_web_requested(
    RUNTIME_MODE, sys.argv[1:], os.environ
)

def _short_hex(b, n=48):
    b = bytes(b or b'')
    return b[:n].hex() + (f"...(+{len(b)-n}B)" if len(b) > n else "")


# ===========================================================================
# v139 UNIFIED UTGame PROTOCOL REGISTRY
# ===========================================================================
# Generated from the shipped UTGame.u.
# Every OnlineRequest_* export is represented. Numeric IDs are attached only
# where we have current/prior evidence; unresolved entries are never guessed.
V139_UTGAME_REQUEST_CATALOG = ({'owner': 'TGOnlineMultiGameRoom', 'name': 'OnlineRequest_CreateRoom', 'export_index': 31634, 'params': (('StructProperty', 'Param'),)}, {'owner': 'TGOnlineMultiGameRoom', 'name': 'OnlineRequest_EnterRoomByRoomId', 'export_index': 31637, 'params': (('StructProperty', 'RoomID'), ('StrProperty', 'Password'))}, {'owner': 'TGOnlineMultiGameRoom', 'name': 'OnlineRequest_TraceFriendByRoomId', 'export_index': 31642, 'params': (('StructProperty', 'RoomID'), ('ByteProperty', 'TraceType'), ('StrProperty', 'Uin'), ('StrProperty', 'Password'))}, {'owner': 'TGOnlineMultiGameRoom', 'name': 'OnlineRequest_QuickEnterRoom', 'export_index': 31644, 'params': (('StructProperty', 'Filter'),)}, {'owner': 'TGOnlineMultiGameRoom', 'name': 'OnlineRequest_LeaveRoom', 'export_index': 31646, 'params': (('IntProperty', 'LeaveReason'),)}, {'owner': 'TGOnlineMultiGameRoom', 'name': 'OnlineRequest_ChangeCamp', 'export_index': 31648, 'params': (('ByteProperty', 'CampIndex'),)}, {'owner': 'TGOnlineMultiGameRoom', 'name': 'OnlineRequest_SetReady', 'export_index': 31649, 'params': ()}, {'owner': 'TGOnlineMultiGameRoom', 'name': 'OnlineRequest_SetReadyWatch', 'export_index': 31650, 'params': ()}, {'owner': 'TGOnlineMultiGameRoom', 'name': 'OnlineRequest_StartMatch', 'export_index': 31651, 'params': ()}, {'owner': 'TGOnlineMultiGameRoom', 'name': 'OnlineRequest_QuitMatch', 'export_index': 31652, 'params': ()}, {'owner': 'TGOnlineMultiGameRoom', 'name': 'OnlineRequest_SetInMatch', 'export_index': 31655, 'params': (('BoolProperty', 'bSuccessful'), ('IntProperty', 'TimespanDuringLoadingGame'))}, {'owner': 'TGOnlineMultiGameRoom', 'name': 'OnlineRequest_JoinMatch', 'export_index': 31657, 'params': (('ByteProperty', 'PlayerMode'),)}, {'owner': 'TGOnlineMultiGameRoom', 'name': 'OnlineRequest_SetGameSettings', 'export_index': 31707, 'params': (('StructProperty', 'Param'),)}, {'owner': 'TGOnlineMultiGameRoom', 'name': 'OnlineRequest_KickPlayer', 'export_index': 31709, 'params': (('StrProperty', 'PlayerUin'),)}, {'owner': 'TGOnlineMultiGameRoom', 'name': 'OnlineRequest_ChangePlayerMode', 'export_index': 31711, 'params': (('ByteProperty', 'PlayerMode'),)}, {'owner': 'TGOnlineMultiGameRoom', 'name': 'OnlineRequest_NotifyUIPanel', 'export_index': 31713, 'params': (('ByteProperty', 'UISystemType'),)}, {'owner': 'TGOnlineMultiGameRoom', 'name': 'OnlineRequest_GetPVETopRankList', 'export_index': 31716, 'params': (('IntProperty', 'ReqModeId'), ('IntProperty', 'ReqMapId'))}, {'owner': 'TGOnlineMultiGameRoom', 'name': 'OnlineRequest_ChangeRoomOwner', 'export_index': 31718, 'params': (('StrProperty', 'PlayerUin'),)}, {'owner': 'TGOnlineMultiGameRoom', 'name': 'OnlineRequest_PlusGameSettings', 'export_index': 31719, 'params': ()}, {'owner': 'TGOnlineMultiGameRoom', 'name': 'OnlineRequest_GetTTMData', 'export_index': 31722, 'params': (('StrProperty', 'PlayerUin'), ('StrProperty', 'PlayerNickName'))}, {'owner': 'TGOnlineMultiGameRoom', 'name': 'OnlineRequest_GetCTMData', 'export_index': 31725, 'params': (('StrProperty', 'PlayerUin'), ('StrProperty', 'PlayerNickName'))}, {'owner': 'TGOnlineMultiGameRoom', 'name': 'OnlineRequest_GetBIOData', 'export_index': 31728, 'params': (('StrProperty', 'PlayerUin'), ('StrProperty', 'PlayerNickName'))}, {'owner': 'TGOnlineMultiGameRoom', 'name': 'OnlineRequest_GetMDMData', 'export_index': 31731, 'params': (('StrProperty', 'PlayerUin'), ('StrProperty', 'PlayerNickName'))}, {'owner': 'TGOnlineMultiGameRoom', 'name': 'OnlineRequest_GetBIO2Data', 'export_index': 31734, 'params': (('StrProperty', 'PlayerUin'), ('StrProperty', 'PlayerNickName'))}, {'owner': 'TGOnlineMultiGameRoom', 'name': 'OnlineRequest_ChangeRoomName', 'export_index': 31736, 'params': (('StrProperty', 'ChangedRoomName'),)}, {'owner': 'TGOnlineMultiGameRoom', 'name': 'OnlineRequest_GetPVEGameStatus', 'export_index': 31769, 'params': (('StrProperty', 'PlayerUin'),)}, {'owner': 'TGOnlineMultiGameRoom', 'name': 'OnlineRequest_JoinLiveGame', 'export_index': 31775, 'params': (('StrProperty', 'PlayerUin'), ('StructProperty', 'RoomID'))}, {'owner': 'TGOnlineMultiGameRoom', 'name': 'OnlineRequest_NotifyQuitLiveGame', 'export_index': 31778, 'params': (('StrProperty', 'PlayerUin'), ('StructProperty', 'RoomID'))}, {'owner': 'TGOnlineAchievement', 'name': 'OnlineRequest_GetRecentlyAchievedInfo', 'export_index': 40100, 'params': (('StrProperty', 'Uin'),)}, {'owner': 'TGOnlineAchievement', 'name': 'OnlineRequest_GetAchievementListByType', 'export_index': 40103, 'params': (('StrProperty', 'Uin'), ('IntProperty', 'AchiType'))}, {'owner': 'TGOnlineAchievement', 'name': 'OnlineRequest_GetFrontAchieved', 'export_index': 40106, 'params': (('StrProperty', 'Uin'), ('IntProperty', 'AchiID'))}, {'owner': 'TGOnlineAchievement', 'name': 'OnlineRequest_GetCardList', 'export_index': 40110, 'params': ()}, {'owner': 'TGOnlineAchievement', 'name': 'OnlineRequest_ModifyCard', 'export_index': 40114, 'params': (('IntProperty', 'AchiCardID'), ('IntProperty', 'AchiID'), ('IntProperty', 'AchiLevel'))}, {'owner': 'TGOnlineAchievement', 'name': 'OnlineRequest_GetCardInfo', 'export_index': 40116, 'params': (('StrProperty', 'Uin'),)}, {'owner': 'TGOnlineAchievement', 'name': 'OnlineRequest_ReportQTAchi', 'export_index': 40120, 'params': (('IntProperty', 'Type'),)}, {'owner': 'TGOnlineAchiScoreAwards', 'name': 'OnlineRequest_GetAward', 'export_index': 40191, 'params': (('IntProperty', 'Level'), ('IntProperty', 'ItemId'), ('IntProperty', 'MoneyType'))}, {'owner': 'TGOnlineActivity', 'name': 'OnlineRequest_ReqCalendar', 'export_index': 40944, 'params': (('IntProperty', 'chPadding'),)}, {'owner': 'TGOnlineActivity', 'name': 'OnlineRequest_ReqPlayerActivityList', 'export_index': 40946, 'params': (('IntProperty', 'chPadding'),)}, {'owner': 'TGOnlineActivity', 'name': 'OnlineRequest_ReqCheckActivity', 'export_index': 40949, 'params': (('IntProperty', 'ActId'), ('IntProperty', 'StageId'))}, {'owner': 'TGOnlineActivity', 'name': 'OnlineRequest_OnActivityButtonClick', 'export_index': 40953, 'params': (('IntProperty', 'ActivityId'), ('IntProperty', 'StageId'), ('IntProperty', 'ButtonType'))}, {'owner': 'TGOnlineActivity', 'name': 'OnlineRequest_OnFillDailyNotice', 'export_index': 40955, 'params': (('IntProperty', 'PlaceHolder'),)}, {'owner': 'TGOnlineActivity', 'name': 'OnlineRequest_ReqCurrOnlineTime', 'export_index': 40956, 'params': ()}, {'owner': 'TGOnlineActivity', 'name': 'OnlineRequest_DailyCheckActivityInfo', 'export_index': 40965, 'params': (('IntProperty', 'ActId'),)}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_NotifyPrecisionPushEffect', 'export_index': 42173, 'params': (('IntProperty', 'SourceTypeId'), ('IntProperty', 'StayTime'), ('IntProperty', 'PressButtonTimes'))}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_ZoneList', 'export_index': 42280, 'params': ()}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_CreateAccount', 'export_index': 42282, 'params': (('StrProperty', 'NickName'),)}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_CheckNickName', 'export_index': 42287, 'params': (('StrProperty', 'NickName'),)}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_ChangeLoginRole', 'export_index': 42290, 'params': (('IntProperty', 'RebelRoleIndex'), ('IntProperty', 'GSDURoleIndex'))}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_SwitchZone', 'export_index': 42296, 'params': (('StrProperty', 'Host'), ('IntProperty', 'Port'), ('IntProperty', 'ChannelId'))}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_CancelSwitchZone', 'export_index': 42297, 'params': ()}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_SetCurrentRole', 'export_index': 42299, 'params': (('StructProperty', 'RolePropId'),)}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_EquipWithProp', 'export_index': 42303, 'params': (('StructProperty', 'OwnerPropId'), ('StructProperty', 'PropId'), ('ByteProperty', 'Location'))}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_TakeoffProp', 'export_index': 42305, 'params': (('StructProperty', 'PropId'),)}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_DropProp', 'export_index': 42307, 'params': (('StructProperty', 'PropId'),)}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_PropAddAvaildPeriod', 'export_index': 42314, 'params': (('StructProperty', 'PropId'), ('ByteProperty', 'PriceIndex'), ('ByteProperty', 'PayType'), ('IntProperty', 'ConvertMP'), ('IntProperty', 'DiscountItemID'), ('IntProperty', 'nCommodityID'))}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_PropRenew', 'export_index': 42318, 'params': (('ArrayProperty', 'PropIdList'), ('IntProperty', 'PropNum'))}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_ExchangeProp', 'export_index': 42320, 'params': (('StructProperty', 'PropId'),)}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_GetFriendStatus', 'export_index': 42330, 'params': ()}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_ReqAddFriend', 'export_index': 42335, 'params': (('StrProperty', 'Uin'), ('StrProperty', 'NickName'), ('StrProperty', 'Message'), ('ByteProperty', 'AddType'))}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_ResAddFriend', 'export_index': 42340, 'params': (('StrProperty', 'Uin'), ('StrProperty', 'NickName'), ('IntProperty', 'nResult'), ('IntProperty', 'RequestId'))}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_DeleteFriend', 'export_index': 42342, 'params': (('StrProperty', 'Uin'),)}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_QueryFriend', 'export_index': 42345, 'params': (('IntProperty', 'QueryType'), ('StrProperty', 'QueryContent'))}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_AddEnemy', 'export_index': 42348, 'params': (('StrProperty', 'Uin'), ('StrProperty', 'NickName'))}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_DeleteEnemy', 'export_index': 42350, 'params': (('StrProperty', 'Uin'),)}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_GetPlayerExps', 'export_index': 42355, 'params': (('ArrayProperty', 'PlayerUins'), ('ByteProperty', 'SystermType'))}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_GetPlayerTeamNames', 'export_index': 42359, 'params': (('ArrayProperty', 'PlayerUins'), ('ByteProperty', 'SystermType'))}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_GetPlayersTeamBadge', 'export_index': 42364, 'params': (('ByteProperty', 'ReqCount'), ('StrProperty', 'ReqUin'), ('ArrayProperty', 'UinList'))}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_AddGroup', 'export_index': 42366, 'params': (('StrProperty', 'NewGroupName'),)}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_DeleteGroup', 'export_index': 42368, 'params': (('IntProperty', 'GroupID'),)}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_RenameGroup', 'export_index': 42371, 'params': (('IntProperty', 'GroupID'), ('StrProperty', 'GroupName'))}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_ModifyFriendGroup', 'export_index': 42374, 'params': (('StrProperty', 'Uin'), ('IntProperty', 'GroupID'))}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_ReqInviteFriend', 'export_index': 42376, 'params': (('StrProperty', 'Uin'),)}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_ResInviteFriend', 'export_index': 42381, 'params': (('StrProperty', 'Uin'), ('IntProperty', 'nResult'), ('IntProperty', 'RequestId'), ('IntProperty', 'Reason'))}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_FollowFriend', 'export_index': 42383, 'params': (('StrProperty', 'Uin'),)}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_ReqFriendDemand', 'export_index': 42388, 'params': (('StrProperty', 'Uin'), ('IntProperty', 'CommodityID'), ('IntProperty', 'AvalidPeriod'), ('StrProperty', 'Message'))}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_ResFriendDemand', 'export_index': 42395, 'params': (('StrProperty', 'Uin'), ('IntProperty', 'CommodityID'), ('IntProperty', 'AvalidPeriod'), ('StrProperty', 'Message'), ('IntProperty', 'nResult'), ('IntProperty', 'RequestId'))}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_GetQQFriendList', 'export_index': 42396, 'params': ()}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_InviteFriendGameTip', 'export_index': 42399, 'params': (('StrProperty', 'ObjectUin'), ('BoolProperty', 'bQQFriend'))}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_GetFriendCardList', 'export_index': 42402, 'params': (('ArrayProperty', 'UinList'),)}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_StealFriendCard', 'export_index': 42405, 'params': (('StrProperty', 'PlayerUin'), ('IntProperty', 'nStealType'))}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_ChatBroadcast', 'export_index': 42411, 'params': (('IntProperty', 'Type'), ('StrProperty', 'Content'), ('ArrayProperty', 'AchiDatas'), ('IntProperty', 'TacticalCommandID'))}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_ChatP2P', 'export_index': 42418, 'params': (('IntProperty', 'Type'), ('StrProperty', 'UinTo'), ('StrProperty', 'NickNameTo'), ('StrProperty', 'Content'), ('ArrayProperty', 'AchiDatas'))}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_ChatSpeaker', 'export_index': 43221, 'params': (('IntProperty', 'Type'), ('StrProperty', 'Content'), ('ArrayProperty', 'AchiDatas'))}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_RemoveMessage', 'export_index': 43223, 'params': (('StructProperty', 'MessageId'),)}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_SetPlayerPreferences', 'export_index': 43224, 'params': ()}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_QuickGame', 'export_index': 43231, 'params': (('IntProperty', 'ModeId'), ('IntProperty', 'MapId'), ('IntProperty', 'SubModeId'), ('BoolProperty', 'bIsInChannel'), ('ArrayProperty', 'MapIdArray'))}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_AllChannelQuickGame', 'export_index': 43236, 'params': (('IntProperty', 'ModeId'), ('IntProperty', 'MapId'), ('IntProperty', 'SubModeId'), ('BoolProperty', 'bInoreMap'))}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_FileVerify', 'export_index': 43242, 'params': (('IntProperty', 'nFileCount'), ('ArrayProperty', 'nFileIdArray'), ('ArrayProperty', 'nFileCrcCodeArray'))}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_UpdateCommodifyFile', 'export_index': 43244, 'params': (('IntProperty', 'nCommodityFileId'),)}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_BuyCommodity', 'export_index': 43258, 'params': (('StrProperty', 'UinCon'), ('IntProperty', 'nPayType'), ('IntProperty', 'ConvertMP'), ('IntProperty', 'DiscountItemID'), ('ByteProperty', 'BuyType'), ('ArrayProperty', 'nCommodityList'), ('StrProperty', 'NickName'))}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_SendMessage', 'export_index': 43263, 'params': (('IntProperty', 'MessageType'), ('StrProperty', 'Uin'), ('StrProperty', 'Remark'), ('StructProperty', 'BuyedCommodity'))}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_ConfirmGift', 'export_index': 43266, 'params': (('StructProperty', 'GiftId'), ('StrProperty', 'NickName'))}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_ExchangeChest', 'export_index': 43267, 'params': ()}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_NotifyFinishNewGuidTask', 'export_index': 43269, 'params': (('ByteProperty', 'nTaskMode'),)}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_UpdateTPValue', 'export_index': 43270, 'params': ()}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_NtfDeleteGifts', 'export_index': 43271, 'params': ()}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_SetSystemSettings', 'export_index': 43272, 'params': ()}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_NtfClientSetting', 'export_index': 43279, 'params': (('IntProperty', 'RecommendLevel'), ('IntProperty', 'CrossHairMode'), ('IntProperty', 'CrossHairColor'), ('IntProperty', 'bUseLeftHand'))}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_GetPVPData', 'export_index': 43282, 'params': (('StrProperty', 'PlayerUin'), ('StrProperty', 'PlayerNickName'))}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_GetPVEData', 'export_index': 43285, 'params': (('StrProperty', 'PlayerUin'), ('StrProperty', 'PlayerNickName'))}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_GetPVMData', 'export_index': 43288, 'params': (('StrProperty', 'PlayerUin'), ('StrProperty', 'PlayerNickName'))}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_GetPPZData', 'export_index': 43291, 'params': (('StrProperty', 'PlayerUin'), ('StrProperty', 'PlayerNickName'))}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_GetPZ2Data', 'export_index': 43294, 'params': (('StrProperty', 'PlayerUin'), ('StrProperty', 'PlayerNickName'))}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_GetSV3Data', 'export_index': 43297, 'params': (('StrProperty', 'PlayerUin'), ('StrProperty', 'PlayerNickName'))}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_GetTeamMatchData', 'export_index': 43300, 'params': (('StrProperty', 'PlayerUin'), ('StrProperty', 'PlayerNickName'))}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_GetDailyRecord', 'export_index': 43302, 'params': (('StrProperty', 'PlayerUin'),)}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_GetOnlinePlayer', 'export_index': 43303, 'params': ()}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_LocalIdlePlayerList', 'export_index': 43304, 'params': ()}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_InvitedLocalPlayers', 'export_index': 43307, 'params': (('ArrayProperty', 'PlayerUinArray'),)}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_SubmitSuggestionList', 'export_index': 43312, 'params': (('ArrayProperty', 'TypeArray'), ('ArrayProperty', 'ContentArray'))}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_SubmitSuggestionSingle', 'export_index': 43315, 'params': (('IntProperty', 'SuggestType'), ('StrProperty', 'SuggestContent'))}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_SubmitVoteResult', 'export_index': 43319, 'params': (('IntProperty', 'VoteType'), ('ArrayProperty', 'VoteResult'))}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_NtfSeverFromClientState', 'export_index': 43320, 'params': ()}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_NtfServerFromVedioRecord', 'export_index': 43322, 'params': (('StructProperty', 'VedioReport'),)}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_NtfSeverOnlineMatchDataIsVisible', 'export_index': 43325, 'params': (('ByteProperty', 'MatchType'), ('BoolProperty', 'bPrivate'))}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_ChangeNickName', 'export_index': 43327, 'params': (('StrProperty', 'NewNickName'),)}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_ClearMatchRecordData', 'export_index': 43328, 'params': ()}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_ClearMatchWinLoseData', 'export_index': 43329, 'params': ()}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_UseFunctionCard', 'export_index': 43332, 'params': (('IntProperty', 'FunctionType'), ('IntProperty', 'SubFunctionType'))}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_NtfExpireCommodityInfo', 'export_index': 43333, 'params': ()}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_StartLuckyDraw', 'export_index': 43335, 'params': (('StrProperty', 'PlayerUin'),)}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_OpenLuckyChest', 'export_index': 43339, 'params': (('StructProperty', 'ValidId'), ('BoolProperty', 'bSpecialBox'), ('IntProperty', 'BoxIndex'))}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_NtfStopLuckyDraw', 'export_index': 43341, 'params': (('StructProperty', 'ValidId'),)}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_FriendLeaveMessage', 'export_index': 43344, 'params': (('StrProperty', 'PlayerUin'), ('StrProperty', 'MessageContent'))}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_NtfReadOfflineMessage', 'export_index': 43347, 'params': (('ArrayProperty', 'MsgIdArray'),)}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_GMBannedPlayer', 'export_index': 43350, 'params': (('StrProperty', 'PlayerUin'), ('IntProperty', 'nHours'))}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_GMFreezePlayer', 'export_index': 43353, 'params': (('StrProperty', 'PlayerUin'), ('IntProperty', 'nDays'))}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_GMCloseRoom', 'export_index': 43355, 'params': (('StructProperty', 'RoomID'),)}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_GMEnforceOffline', 'export_index': 43357, 'params': (('StrProperty', 'PlayerUin'),)}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_StartQQTalk', 'export_index': 43358, 'params': ()}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_TeamBindQTalk', 'export_index': 43394, 'params': (('StructProperty', 'stRoomMsg'),)}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_GetMyTeamQTID', 'export_index': 43396, 'params': (('IntProperty', 'nType'),)}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_ChangeTeam', 'export_index': 43398, 'params': (('IntProperty', 'TeamIndex'),)}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_LotteryBuyBullet', 'export_index': 43401, 'params': (('IntProperty', 'Count'),)}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_LotteryFire', 'export_index': 43403, 'params': (('IntProperty', 'Area'),)}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_LotteryExchange', 'export_index': 43405, 'params': (('IntProperty', 'Index'),)}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_LotteryMarquee', 'export_index': 43407, 'params': (('IntProperty', 'Idx'),)}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_CheckFPSCommodityLibraryVersion', 'export_index': 43433, 'params': ()}, {'owner': 'TGOnlineComplaint', 'name': 'OnlineRequest_ReqCommitComplaint', 'export_index': 44777, 'params': (('StrProperty', 'TargetQQ'), ('IntProperty', 'ComplaintClassify'), ('StrProperty', 'Content'), ('StructProperty', 'RoomID'), ('IntProperty', 'Time'))}, {'owner': 'TGOnlineFriendImpression', 'name': 'OnlineRequest_GetFriendImpressions', 'export_index': 44794, 'params': (('StrProperty', 'PlayerUin'),)}, {'owner': 'TGOnlineFriendImpression', 'name': 'OnlineRequest_SetFriendImpression', 'export_index': 44797, 'params': (('StrProperty', 'PlayerUin'), ('IntProperty', 'ImpId'))}, {'owner': 'TGOnlineHappyMatch', 'name': 'OnlineRequest_ReqEnterHappyMatch', 'export_index': 45523, 'params': (('StrProperty', 'Uin'), ('IntProperty', 'EnterReason'), ('IntProperty', 'Mode'))}, {'owner': 'TGOnlineHappyMatch', 'name': 'OnlineRequest_ReqLeaveHappyMatch', 'export_index': 45525, 'params': (('IntProperty', 'LeaveReason'),)}, {'owner': 'TGOnlineHappyMatch', 'name': 'OnlineRequest_ReqHappyMatchDsList', 'export_index': 45527, 'params': (('IntProperty', 'ReqReason'),)}, {'owner': 'TGOnlineHappyMatch', 'name': 'OnlineRequest_NtfEnterHappyMatchMode', 'export_index': 45529, 'params': (('IntProperty', 'ReqReason'),)}, {'owner': 'TGOnlineHappyMatch', 'name': 'OnlineRequest_ReqCurrentMatchingPlayerCount', 'export_index': 45532, 'params': (('StrProperty', 'Uin'), ('IntProperty', 'ReqReason'))}, {'owner': 'TGOnlineHappyMatch', 'name': 'OnlineRequest_ReqHappyMatchTimeCheck', 'export_index': 45534, 'params': (('IntProperty', 'ReqReason'),)}, {'owner': 'TGOnlineHappyMatch', 'name': 'OnlineRequest_ReqHappyPointExchange', 'export_index': 45536, 'params': (('IntProperty', 'HappyPointAmount'),)}, {'owner': 'TGOnlineHappyMatch', 'name': 'OnlineRequest_ReqHappyMatchDsList_Test', 'export_index': 45539, 'params': (('IntProperty', 'ReqReason'),)}, {'owner': 'TGOnlineModeGuide', 'name': 'OnlineRequest_InviteJoinMatchModeTeam', 'export_index': 49337, 'params': (('IntProperty', 'TeamID'), ('StructProperty', 'stModeGameInfo'), ('ArrayProperty', 'FriendUins'), ('ArrayProperty', 'TeamUins'))}, {'owner': 'TGOnlineModeGuide', 'name': 'OnlineRequest_AcceptOrRefuseJoinTeam', 'export_index': 49341, 'params': (('IntProperty', 'TeamID'), ('BoolProperty', 'IsAccept'), ('IntProperty', 'nReason'))}, {'owner': 'TGOnlineModeGuide', 'name': 'OnlineRequest_ExitTheTeam', 'export_index': 49344, 'params': (('IntProperty', 'TeamID'), ('StrProperty', 'Uin'))}, {'owner': 'TGOnlineModeGuide', 'name': 'OnlineRequest_RemoveSomeone', 'export_index': 49347, 'params': (('IntProperty', 'TeamID'), ('StrProperty', 'Uin'))}, {'owner': 'TGOnlineModeGuide', 'name': 'OnlineRequest_ReadyGame', 'export_index': 49353, 'params': (('IntProperty', 'TeamID'), ('StrProperty', 'Uin'), ('IntProperty', 'ModeId'), ('IntProperty', 'SubModeId'), ('IntProperty', 'MapId'))}, {'owner': 'TGOnlineModeGuide', 'name': 'OnlineRequest_CancelReadyGame', 'export_index': 49356, 'params': (('IntProperty', 'TeamID'), ('StrProperty', 'Uin'))}, {'owner': 'TGOnlineModeGuide', 'name': 'OnlineRequest_TeamMatchGame', 'export_index': 49359, 'params': (('StructProperty', 'MatchData'), ('BoolProperty', 'bContainedType'))}, {'owner': 'TGOnlineModeGuide', 'name': 'OnlineRequest_TeamStopMatchGame', 'export_index': 49363, 'params': (('IntProperty', 'TeamID'), ('StrProperty', 'Uin'), ('BoolProperty', 'bTimeout'))}, {'owner': 'TGOnlineModeGuide', 'name': 'OnlineRequest_TeamNtfPlayerStatus', 'export_index': 49367, 'params': (('ByteProperty', 'CurPlayerStatus'), ('IntProperty', 'TeamID'), ('StrProperty', 'Uin'))}, {'owner': 'TGOnlineModeGuide', 'name': 'OnlineRequest_DismissTeam', 'export_index': 49370, 'params': (('IntProperty', 'TeamID'), ('StrProperty', 'Uin'))}, {'owner': 'TGOnlineModeGuide', 'name': 'OnlineRequest_ChangeModeGame', 'export_index': 49374, 'params': (('IntProperty', 'TeamID'), ('ArrayProperty', 'ModeIndex'))}, {'owner': 'TGOnlineModeGuide', 'name': 'OnlineRequest_SingleMatch', 'export_index': 49381, 'params': (('StrProperty', 'PlayerUin'), ('IntProperty', 'ModeId'), ('IntProperty', 'SubModeId'), ('ArrayProperty', 'MapId'), ('BoolProperty', 'bContainedType'))}, {'owner': 'TGOnlineModeGuide', 'name': 'OnlineRequest_StopSingleMatch', 'export_index': 49384, 'params': (('StrProperty', 'PlayerUin'), ('BoolProperty', 'bTimeout'))}, {'owner': 'TGOnlinePersonalGame', 'name': 'OnlineRequest_ReadyPersonalMatch', 'export_index': 50247, 'params': (('IntProperty', 'CurModeId'), ('BoolProperty', 'bEnableVideoRecord'))}, {'owner': 'TGOnlinePersonalGame', 'name': 'OnlineRequest_GetPersonalMatchTopList', 'export_index': 50248, 'params': ()}, {'owner': 'TGOnlinePersonalGame', 'name': 'OnlineRequest_UnReadyPersonalMatch', 'export_index': 50250, 'params': (('BoolProperty', 'bIsTimeOut'),)}, {'owner': 'TGOnlinePersonalGame', 'name': 'OnlineRequest_GetSingleMatchData', 'export_index': 50253, 'params': (('StrProperty', 'PlayerUin'), ('StrProperty', 'PlayerNickName'))}, {'owner': 'TGOnlinePersonalGame', 'name': 'OnlineRequest_NotifyServerEnterSingleMatch', 'export_index': 50254, 'params': ()}, {'owner': 'TGOnlinePersonalGame', 'name': 'OnlineRequest_InviteJoinPMTeam', 'export_index': 50261, 'params': (('IntProperty', 'PMTeamId'), ('StrProperty', 'PlayerUin'), ('ArrayProperty', 'FriendUins'), ('ArrayProperty', 'TeamUins'))}, {'owner': 'TGOnlinePersonalGame', 'name': 'OnlineRequest_JoinPMTeam', 'export_index': 50265, 'params': (('IntProperty', 'PMTeamId'), ('BoolProperty', 'bIsAgree'), ('IntProperty', 'RefuseReason'))}, {'owner': 'TGOnlinePersonalGame', 'name': 'OnlineRequest_QuitPMTeam', 'export_index': 50268, 'params': (('IntProperty', 'PMTeamId'), ('StrProperty', 'PlayerUin'))}, {'owner': 'TGOnlinePersonalGame', 'name': 'OnlineRequest_RemovePMTeam', 'export_index': 50271, 'params': (('IntProperty', 'PMTeamId'), ('StrProperty', 'PlayerUin'))}, {'owner': 'TGOnlinePersonalGame', 'name': 'OnlineRequest_ReadyPMTeam', 'export_index': 50275, 'params': (('IntProperty', 'PMTeamId'), ('StrProperty', 'PlayerUin'), ('BoolProperty', 'bEnableVideoRecord'))}, {'owner': 'TGOnlinePersonalGame', 'name': 'OnlineRequest_CancelReadyPMTeam', 'export_index': 50278, 'params': (('IntProperty', 'PMTeamId'), ('StrProperty', 'PlayerUin'))}, {'owner': 'TGOnlinePersonalGame', 'name': 'OnlineRequest_EnterMatchPMTeam', 'export_index': 50283, 'params': (('IntProperty', 'PMTeamId'), ('StrProperty', 'PlayerUin'), ('IntProperty', 'CurModeId'), ('BoolProperty', 'bEnableVideoRecord'))}, {'owner': 'TGOnlinePersonalGame', 'name': 'OnlineRequest_StopMatchPMTeam', 'export_index': 50287, 'params': (('IntProperty', 'PMTeamId'), ('StrProperty', 'PlayerUin'), ('BoolProperty', 'bIsTimeOut'))}, {'owner': 'TGOnlinePersonalGame', 'name': 'OnlineRequest_DismissPMTeam', 'export_index': 50290, 'params': (('IntProperty', 'PMTeamId'), ('StrProperty', 'PlayerUin'))}, {'owner': 'TGOnlinePersonalGame', 'name': 'OnlineRequest_NtfInGamePMTeam', 'export_index': 50293, 'params': (('IntProperty', 'PMTeamId'), ('StrProperty', 'PlayerUin'))}, {'owner': 'TGOnlinePersonalGame', 'name': 'OnlineRequest_NtfQuitGamePMTeam', 'export_index': 50296, 'params': (('IntProperty', 'PMTeamId'), ('StrProperty', 'PlayerUin'))}, {'owner': 'TGOnlinePersonalGame', 'name': 'OnlineRequest_NtfEndGamePMTeam', 'export_index': 50299, 'params': (('IntProperty', 'PMTeamId'), ('StrProperty', 'PlayerUin'))}, {'owner': 'TGOnlinePersonalGame', 'name': 'OnlineRequest_NtfLeaderPMEnterMatchState', 'export_index': 50302, 'params': (('IntProperty', 'PMTeamId'), ('StrProperty', 'PlayerUin'))}, {'owner': 'TGOnlinePersonalGame', 'name': 'OnlineRequest_NtfLeaderPMCancelMatchState', 'export_index': 50305, 'params': (('IntProperty', 'PMTeamId'), ('StrProperty', 'PlayerUin'))}, {'owner': 'TGOnlinePersonalGame', 'name': 'OnlineRequest_GetProhibitPMMatchInfo', 'export_index': 50306, 'params': ()}, {'owner': 'TGOnlinePersonalGame', 'name': 'OnlineRequest_GetPMMatchSeasonTime', 'export_index': 50307, 'params': ()}, {'owner': 'TGOnlinePersonalGame', 'name': 'OnlineRequest_PMMatchDSList', 'export_index': 50310, 'params': (('StrProperty', 'PlayerUin'), ('ByteProperty', 'CurMatchType'))}, {'owner': 'TGOnlineRankList', 'name': 'OnlineRequest_ReqRankTotal', 'export_index': 51259, 'params': (('StrProperty', 'Uin'), ('IntProperty', 'RankListType'))}, {'owner': 'TGOnlineRankList', 'name': 'OnlineRequest_ReqRankDaily', 'export_index': 51263, 'params': (('StrProperty', 'Uin'), ('IntProperty', 'RankListType'), ('IntProperty', 'Date'))}, {'owner': 'TGOnlineRankList', 'name': 'OnlineRequest_ReqRankListAward', 'export_index': 51268, 'params': (('StrProperty', 'Uin'), ('IntProperty', 'RankListType'), ('IntProperty', 'Date'), ('IntProperty', 'pos'))}, {'owner': 'TGOnlineRankList', 'name': 'OnlineRequest_ReqCheckRankListAward', 'export_index': 51273, 'params': (('StrProperty', 'Uin'), ('IntProperty', 'RankListType'), ('IntProperty', 'Date'), ('IntProperty', 'pos'))}, {'owner': 'TGOnlineTask', 'name': 'OnlineRequest_AcceptTask', 'export_index': 52612, 'params': (('IntProperty', 'TaskID'),)}, {'owner': 'TGOnlineTask', 'name': 'OnlineRequest_AcceptRandomTask', 'export_index': 52614, 'params': (('IntProperty', 'TaskGroupID'),)}, {'owner': 'TGOnlineTask', 'name': 'OnlineRequest_AbandonTask', 'export_index': 52616, 'params': (('IntProperty', 'TaskID'),)}, {'owner': 'TGOnlineTask', 'name': 'OnlineRequest_SubmitTask', 'export_index': 52619, 'params': (('IntProperty', 'TaskID'), ('IntProperty', 'AwardIndex'))}, {'owner': 'TGOnlineTask', 'name': 'OnlineRequest_UpdateTaskProgress', 'export_index': 52623, 'params': (('IntProperty', 'TaskID'), ('IntProperty', 'NodeIndex'), ('IntProperty', 'NodeValue'))}, {'owner': 'TGOnlineTask', 'name': 'OnlineRequest_GetPlayerTaskProgress', 'export_index': 52625, 'params': (('IntProperty', 'TaskID'),)}, {'owner': 'TGOnlineTask', 'name': 'OnlineRequest_TriggerTimeout', 'export_index': 52631, 'params': (('IntProperty', 'TaskID'), ('IntProperty', 'TaskNodeIndex'))}, {'owner': 'TGOnlineTask', 'name': 'OnlineRequest_TriggerOnlineDuration', 'export_index': 52634, 'params': (('IntProperty', 'TaskID'), ('IntProperty', 'TaskNodeIndex'))}, {'owner': 'TGOnlineTask', 'name': 'OnlineRequest_SubmitSurvey', 'export_index': 52673, 'params': (('IntProperty', 'TaskID'), ('IntProperty', 'SurveyId'), ('ArrayProperty', 'Results'))}, {'owner': 'TGOnlineTask', 'name': 'OnlineRequest_StartQTOnlineTime', 'export_index': 52675, 'params': (('StrProperty', 'RoomID'),)}, {'owner': 'TGOnlineTask', 'name': 'OnlineRequest_EndQTOnlineTime', 'export_index': 52677, 'params': (('StrProperty', 'RoomID'),)}, {'owner': 'TGOnlineTask', 'name': 'OnlineRequest_ReqQTOnlineRemainTime', 'export_index': 52681, 'params': (('StrProperty', 'RoomID'), ('IntProperty', 'TaskID'), ('IntProperty', 'NodeIndex'))}, {'owner': 'TGOnlineTask', 'name': 'OnlineRequest_RequestClientFinishMission', 'export_index': 52684, 'params': (('IntProperty', 'MissionID'), ('IntProperty', 'TargetIndex'))}, {'owner': 'TGOnlineTeamGame', 'name': 'OnlineRequest_InviteJoinTeamMatch', 'export_index': 53718, 'params': (('ArrayProperty', 'PlayerUins'),)}, {'owner': 'TGOnlineTeamGame', 'name': 'OnlineRequest_ResInviteJoinTeamMatch', 'export_index': 53722, 'params': (('BoolProperty', 'bAgree'), ('IntProperty', 'CurTeamId'), ('IntProperty', 'ReasonValue'))}, {'owner': 'TGOnlineTeamGame', 'name': 'OnlineRequest_SetReady', 'export_index': 53724, 'params': (('StrProperty', 'PlayerUin'),)}, {'owner': 'TGOnlineTeamGame', 'name': 'OnlineRequest_UnSetReady', 'export_index': 53726, 'params': (('StrProperty', 'PlayerUin'),)}, {'owner': 'TGOnlineTeamGame', 'name': 'OnlineRequest_EnterTeamMatch', 'export_index': 53729, 'params': (('StrProperty', 'PlayerUin'), ('IntProperty', 'SelectedMatchMode'))}, {'owner': 'TGOnlineTeamGame', 'name': 'OnlineRequest_QuitEnterTeamMatch', 'export_index': 53732, 'params': (('StrProperty', 'PlayerUin'), ('BoolProperty', 'bIsTimeOut'))}, {'owner': 'TGOnlineTeamGame', 'name': 'OnlineRequest_QuitTeamMatchUI', 'export_index': 53734, 'params': (('StrProperty', 'PlayerUin'),)}, {'owner': 'TGOnlineTeamGame', 'name': 'OnlineRequest_DissolveTeamMatch', 'export_index': 53737, 'params': (('StrProperty', 'PlayerUin'), ('IntProperty', 'CurTeamId'))}, {'owner': 'TGOnlineTeamGame', 'name': 'OnlineRequest_KickTeamMatchMember', 'export_index': 53740, 'params': (('StrProperty', 'KickedPlayerUin'), ('StrProperty', 'ReqPlayerUin'))}, {'owner': 'TGOnlineTeamGame', 'name': 'OnlineRequest_StartTeamGame', 'export_index': 53742, 'params': (('StrProperty', 'PlayerUin'),)}, {'owner': 'TGOnlineTeamGame', 'name': 'OnlineRequest_BreakTeamGame', 'export_index': 53744, 'params': (('StrProperty', 'PlayerUin'),)}, {'owner': 'TGOnlineTeamGame', 'name': 'OnlineRequest_EndTeamGame', 'export_index': 53746, 'params': (('StrProperty', 'PlayerUin'),)}, {'owner': 'TGOnlineTeamGame', 'name': 'OnlineRequest_VeriyTeamGroupName', 'export_index': 53752, 'params': (('StrProperty', 'GroupName'),)}, {'owner': 'TGOnlineTeamGame', 'name': 'OnlineRequest_CreateTeamGroup', 'export_index': 53753, 'params': ()}, {'owner': 'TGOnlineTeamGame', 'name': 'OnlineRequest_GetTeamGroupInfo', 'export_index': 53756, 'params': (('StructProperty', 'ReqTeamId'), ('IntProperty', 'ReqTeamGroupId'))}, {'owner': 'TGOnlineTeamGame', 'name': 'OnlineRequest_InviteJoinTeamGroup', 'export_index': 53759, 'params': (('StrProperty', 'InvitedUin'), ('BoolProperty', 'bIsTempGroup'))}, {'owner': 'TGOnlineTeamGame', 'name': 'OnlineRequest_NtfInvitedJoinGroupResult', 'export_index': 53763, 'params': (('BoolProperty', 'bIsAgree'), ('StrProperty', 'InviteUin'), ('BoolProperty', 'bIsTempGroup'))}, {'owner': 'TGOnlineTeamGame', 'name': 'OnlineRequest_DeleteTeamGroupMember', 'export_index': 53768, 'params': (('StrProperty', 'ReqUin'), ('ArrayProperty', 'DeletedUins'), ('BoolProperty', 'bIsTempGroup'))}, {'owner': 'TGOnlineTeamGame', 'name': 'OnlineRequest_SetTeamGroupPost', 'export_index': 53771, 'params': (('StrProperty', 'ChangedUin'), ('ByteProperty', 'GroupPost'))}, {'owner': 'TGOnlineTeamGame', 'name': 'OnlineRequest_QuitTeamGroup', 'export_index': 53773, 'params': (('BoolProperty', 'bIsTempGroup'),)}, {'owner': 'TGOnlineTeamGame', 'name': 'OnlineRequest_GetTeamGroupList', 'export_index': 53774, 'params': ()}, {'owner': 'TGOnlineTeamGame', 'name': 'OnlineRequest_GetTeamGroupRankList', 'export_index': 53775, 'params': ()}, {'owner': 'TGOnlineTeamGame', 'name': 'OnlineRequest_DissolveTeamGroup', 'export_index': 53778, 'params': (('IntProperty', 'GroupID'), ('BoolProperty', 'bIsTempGroup'))}, {'owner': 'TGOnlineTeamGame', 'name': 'OnlineRequest_GetTMMatchSeasonTime', 'export_index': 53779, 'params': ()}, {'owner': 'TGOnlineTeamGame', 'name': 'OnlineRequest_GetTeamMatchRecord', 'export_index': 53782, 'params': (('StructProperty', 'ReqTeamId'), ('IntProperty', 'ReqTeamGroupId'))}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_ApplyToJoinTeam', 'export_index': 55001, 'params': (('StructProperty', 'TeamID'), ('StrProperty', 'PlayerUin'), ('StrProperty', 'PlayerNickName'))}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_ApproveList', 'export_index': 55005, 'params': (('StructProperty', 'TeamID'), ('StrProperty', 'PlayerUin'), ('StrProperty', 'PlayerNickName'))}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_ApproveJoinResult', 'export_index': 55010, 'params': (('ArrayProperty', 'ApproveList'), ('StrProperty', 'DealPlayerUin'), ('BoolProperty', 'bAgree'))}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_ConfirmJoin', 'export_index': 55015, 'params': (('StructProperty', 'TeamID'), ('StructProperty', 'InvitedID'), ('StrProperty', 'PlayerUin'), ('BoolProperty', 'bAgree'))}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_FireMember', 'export_index': 55019, 'params': (('StrProperty', 'OwnerUin'), ('StrProperty', 'FiredPlayerUin'), ('StrProperty', 'SafeCode'))}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_PromotionMember', 'export_index': 55023, 'params': (('StrProperty', 'OwnerUin'), ('StrProperty', 'PromotionPlayerUin'), ('ByteProperty', 'PromotionPost'))}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_DemotionMember', 'export_index': 55027, 'params': (('StrProperty', 'OwnerUin'), ('StrProperty', 'DemotionPlayerUin'), ('ByteProperty', 'DemotionPost'))}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_QuitTeam', 'export_index': 55029, 'params': (('StrProperty', 'OwnerUin'),)}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_ExtendTeam', 'export_index': 55032, 'params': (('StrProperty', 'OwnerUin'), ('IntProperty', 'TotalPalyerCount'))}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_HandOverTeam', 'export_index': 55036, 'params': (('StrProperty', 'OwnerUin'), ('StrProperty', 'ReceiverUin'), ('StrProperty', 'SafeCode'))}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_ResDealHandOver', 'export_index': 55041, 'params': (('StrProperty', 'OwnerUin'), ('StrProperty', 'CaptainUin'), ('BoolProperty', 'bIsAgree'), ('StrProperty', 'SafeCode'))}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_InvitePlayerJoin', 'export_index': 55044, 'params': (('StrProperty', 'OwnerUin'), ('StrProperty', 'InvitedPlayerUin'))}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_DissolveTeam', 'export_index': 55047, 'params': (('StrProperty', 'OwnerUin'), ('StrProperty', 'SafeCode'))}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_CancelDissolveTeam', 'export_index': 55050, 'params': (('StrProperty', 'OwnerUin'), ('StrProperty', 'SafeCode'))}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_MergeTeam', 'export_index': 55053, 'params': (('StrProperty', 'OwnerUin'), ('StrProperty', 'TeamName'))}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_NotifyMergedResult', 'export_index': 55058, 'params': (('StrProperty', 'OwnerUin'), ('StructProperty', 'TeamID'), ('BoolProperty', 'bIsAgree'), ('StrProperty', 'SafeCode'))}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_ConfirmMergeResult', 'export_index': 55061, 'params': (('StructProperty', 'TeamID'), ('BoolProperty', 'bIsAgree'))}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_TeamPray', 'export_index': 55063, 'params': (('StrProperty', 'OwnerUin'),)}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_CreateTeam', 'export_index': 55068, 'params': (('StrProperty', 'PlayerUin'), ('StrProperty', 'TeamName'), ('StrProperty', 'SafeCode'), ('StrProperty', 'EmailContent'))}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_PublishRecruit', 'export_index': 55074, 'params': (('StrProperty', 'PlayerUin'), ('IntProperty', 'RecruitType'), ('IntProperty', 'RecruitLevelNumber'), ('StrProperty', 'RecruitInfo'), ('BoolProperty', 'bPublish'))}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_GetDetailTeamInfo', 'export_index': 55076, 'params': (('StrProperty', 'PlayerUin'),)}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_GetMemberList', 'export_index': 55079, 'params': (('StrProperty', 'PlayerUin'), ('BoolProperty', 'bIsAll'))}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_GetOtherTeamInfo', 'export_index': 55082, 'params': (('StrProperty', 'PlayerUin'), ('StructProperty', 'TeamID'))}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_SearchTeamByName', 'export_index': 55086, 'params': (('StrProperty', 'PlayerUin'), ('StrProperty', 'TeamName'), ('ByteProperty', 'nTeamScaleType'))}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_CheckTeamName', 'export_index': 55089, 'params': (('StrProperty', 'PlayerUin'), ('StrProperty', 'TeamName'))}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_ChangeTeamName', 'export_index': 55092, 'params': (('StrProperty', 'NewTeamName'), ('StrProperty', 'SafeCode'))}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_ChangeSafeCode', 'export_index': 55095, 'params': (('StrProperty', 'OldSafeCode'), ('StrProperty', 'NewSafeCode'))}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_ResetSafeCode', 'export_index': 55098, 'params': (('StrProperty', 'EmailContent'), ('StrProperty', 'NewSafeCode'))}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_ChangeCertifiedEmail', 'export_index': 55101, 'params': (('StrProperty', 'NewEmailContent'), ('StrProperty', 'OldEmailContent'))}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_GetBulletin', 'export_index': 55103, 'params': (('StrProperty', 'OwnerUin'),)}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_SetBulletin', 'export_index': 55107, 'params': (('StrProperty', 'OwnerUin'), ('ByteProperty', 'BulletinIndex'), ('StrProperty', 'BulletinContent'))}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_GetTeamNews', 'export_index': 55109, 'params': (('StrProperty', 'OwnerUin'),)}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_TeamIntroduction', 'export_index': 55111, 'params': (('StrProperty', 'IntroductionContent'),)}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_GetTeamRankList', 'export_index': 55116, 'params': (('StrProperty', 'OwnerUin'), ('IntProperty', 'PageIndex'), ('BoolProperty', 'bLookSelf'), ('ByteProperty', 'nTeamScaleType'))}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_BanSpeech', 'export_index': 55119, 'params': (('StrProperty', 'OwnerUin'), ('StrProperty', 'ObjPlayerUin'))}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_CancelBanSpeech', 'export_index': 55122, 'params': (('StrProperty', 'OwnerUin'), ('StrProperty', 'ObjPlayerUin'))}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_SetBadge', 'export_index': 55127, 'params': (('StrProperty', 'OwnerUin'), ('IntProperty', 'IconItemID'), ('IntProperty', 'FrameItemID'), ('IntProperty', 'BackgroundItemID'))}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_BuyBadge', 'export_index': 55131, 'params': (('StrProperty', 'OwnerUin'), ('ArrayProperty', 'BuyList'))}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_RenewBadge', 'export_index': 55133, 'params': (('StructProperty', 'RenewPropInfo'),)}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_GetBadgeList', 'export_index': 55135, 'params': (('StrProperty', 'OwnerUin'),)}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_TeamLeaderNotice', 'export_index': 55138, 'params': (('StrProperty', 'PlayerUin'), ('StrProperty', 'NoticeContent'))}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_RecruitMemberList', 'export_index': 55140, 'params': (('StrProperty', 'PlayerUin'),)}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_CreateNewTeamMemberGroup', 'export_index': 55143, 'params': (('StrProperty', 'PlayerUin'), ('StrProperty', 'MemberGroupName'))}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_ChangeTeamMemberGroupInfo', 'export_index': 55147, 'params': (('StrProperty', 'PlayerUin'), ('StrProperty', 'MemberGroupName'), ('IntProperty', 'MemberGroupId'))}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_DismissTeamMemberGroup', 'export_index': 55150, 'params': (('StrProperty', 'PlayerUin'), ('IntProperty', 'MemberGroupId'))}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_GetTeamMemberGroupList', 'export_index': 55153, 'params': (('StrProperty', 'PlayerUin'), ('BoolProperty', 'bNeedCalculateScore'))}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_ChangeTeamMemberInOtherGroup', 'export_index': 55157, 'params': (('StrProperty', 'ManagerUin'), ('StrProperty', 'PlayerUin'), ('ByteProperty', 'MemberGroupId'))}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_GetSelfReputationList', 'export_index': 55158, 'params': ()}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_GetWarehouseProps', 'export_index': 55160, 'params': (('IntProperty', 'nWareHouseId'),)}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_DrawProp', 'export_index': 55162, 'params': (('StructProperty', 'nPropId'),)}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_DonateProp', 'export_index': 55165, 'params': (('StructProperty', 'nPropId'), ('IntProperty', 'nWareHouseId'))}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_MoveProp', 'export_index': 55169, 'params': (('StructProperty', 'nPropId'), ('IntProperty', 'nOldWarehouseId'), ('IntProperty', 'nNewWarehouseId'))}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_SetUseRightByWarehouse', 'export_index': 55172, 'params': (('IntProperty', 'nWareHouseId'), ('ByteProperty', 'nUseRight'))}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_GetWarehouseList', 'export_index': 55173, 'params': ()}, {'owner': 'TGOnlineTechnicalGame', 'name': 'OnlineRequest_TMMatchDSList', 'export_index': 55663, 'params': (('StrProperty', 'PlayerUin'),)}, {'owner': 'TGOnlineTechnicalGame', 'name': 'OnlineRequest_InviteJoinTMTeam', 'export_index': 55682, 'params': (('IntProperty', 'TMTeamId'), ('StructProperty', 'LeaderInfo'), ('ByteProperty', 'PayType'), ('ArrayProperty', 'FriendUins'), ('ArrayProperty', 'TeamUins'))}, {'owner': 'TGOnlineTechnicalGame', 'name': 'OnlineRequest_JoinTMTeam', 'export_index': 55686, 'params': (('IntProperty', 'TMTeamId'), ('BoolProperty', 'bIsAgree'), ('IntProperty', 'RefuseReason'))}, {'owner': 'TGOnlineTechnicalGame', 'name': 'OnlineRequest_QuitTMTeam', 'export_index': 55689, 'params': (('IntProperty', 'TMTeamId'), ('StrProperty', 'PlayerUin'))}, {'owner': 'TGOnlineTechnicalGame', 'name': 'OnlineRequest_DismissTeam', 'export_index': 55692, 'params': (('IntProperty', 'TMTeamId'), ('StrProperty', 'PlayerUin'))}, {'owner': 'TGOnlineTechnicalGame', 'name': 'OnlineRequest_RemoveTMTeam', 'export_index': 55695, 'params': (('IntProperty', 'TMTeamId'), ('StrProperty', 'PlayerUin'))}, {'owner': 'TGOnlineTechnicalGame', 'name': 'OnlineRequest_ReadyMatch', 'export_index': 55703, 'params': (('IntProperty', 'TMTeamId'), ('StrProperty', 'PlayerUin'))}, {'owner': 'TGOnlineTechnicalGame', 'name': 'OnlineRequest_CancelReady', 'export_index': 55706, 'params': (('IntProperty', 'TMTeamId'), ('StrProperty', 'PlayerUin'))}, {'owner': 'TGOnlineTechnicalGame', 'name': 'OnlineRequest_TeamStopMatch', 'export_index': 55710, 'params': (('IntProperty', 'TMTeamId'), ('StrProperty', 'PlayerUin'), ('BoolProperty', 'TimeOut'))}, {'owner': 'TGOnlineTechnicalGame', 'name': 'OnlineRequest_ChangePayType', 'export_index': 55713, 'params': (('IntProperty', 'TMTeamId'), ('ByteProperty', 'PayType'))}, {'owner': 'TGOnlineTechnicalGame', 'name': 'OnlineRequest_ChangeMode', 'export_index': 55717, 'params': (('IntProperty', 'TMTeamId'), ('ByteProperty', 'ModeIndex'), ('IntProperty', 'Money'))}, {'owner': 'TGOnlineMultiGameLobby', 'name': 'OnlineRequest_ChannelList', 'export_index': 77886, 'params': (('IntProperty', 'MainChannelID'),)}, {'owner': 'TGOnlineMultiGameLobby', 'name': 'OnlineRequest_MainChannelList', 'export_index': 77887, 'params': ()}, {'owner': 'TGOnlineMultiGameLobby', 'name': 'OnlineRequest_GetChannelPingValue', 'export_index': 77888, 'params': ()}, {'owner': 'TGOnlineMultiGameLobby', 'name': 'OnlineRequest_QueryRoomList', 'export_index': 77892, 'params': (('StructProperty', 'Filter'), ('IntProperty', 'Start'), ('IntProperty', 'Count'))}, {'owner': 'TGOnlineMultiGameLobby', 'name': 'OnlineRequest_QueryRoomInfoById', 'export_index': 77894, 'params': (('StructProperty', 'RoomID'),)}, {'owner': 'TGOnlineMultiGameLobby', 'name': 'OnlineRequest_QueryExpertList', 'export_index': 77897, 'params': (('IntProperty', 'SortBy'), ('IntProperty', 'Count'))}, {'owner': 'TGOnlineMultiGameLobby', 'name': 'OnlineRequest_SwitchLocalChannel', 'export_index': 77899, 'params': (('IntProperty', 'SubChannelID'),)}, {'owner': 'TGOnlineMultiGameLobby', 'name': 'OnlineRequest_AllSubChannelList', 'export_index': 77916, 'params': ()}, {'owner': 'TGOnlineMultiGameLobby', 'name': 'OnlineRequest_AllFindRoomList', 'export_index': 77918, 'params': (('StrProperty', 'PlayerUin'),)}, {'owner': 'TGWithCross', 'name': 'OnlineRequest_CreateQTalkRoom', 'export_index': 78563, 'params': (('ByteProperty', 'CurQQTalkStatus'), ('StrProperty', 'RoomID'), ('StrProperty', 'subRoomID'), ('StrProperty', 'lastRoomID'))}, {'owner': 'TGWithCross', 'name': 'OnlineRequest_EnterQTalkRoom', 'export_index': 78568, 'params': (('ByteProperty', 'CurQQTalkStatus'), ('StrProperty', 'RoomID'), ('StrProperty', 'subRoomID'), ('StrProperty', 'lastRoomID'))}, {'owner': 'TGWithCross', 'name': 'OnlineRequest_OpenQTalkTeamRoom', 'export_index': 78574, 'params': (('StructProperty', 'qwRoomID'), ('IntProperty', 'dwIDC'), ('IntProperty', 'dwISP'), ('BoolProperty', 'bRegular'), ('BoolProperty', 'bUseMyName'))}, {'owner': 'TGWithCross', 'name': 'OnlineRequest_QuitQTalkRoom', 'export_index': 78576, 'params': (('ByteProperty', 'CurQQTalkStatus'),)}, {'owner': 'TGWithCross', 'name': 'OnlineRequest_ShowSettingPanel', 'export_index': 78578, 'params': (('BoolProperty', 'bShow'),)}, {'owner': 'TGWithCross', 'name': 'OnlineRequest_ShowQTRoomPanel', 'export_index': 78580, 'params': (('BoolProperty', 'bShow'),)}, {'owner': 'TGWithCross', 'name': 'OnlineRequest_ShowTeamBindPanel', 'export_index': 78582, 'params': (('BoolProperty', 'bShow'),)}, {'owner': 'TGWithCross', 'name': 'OnlineRequest_OpenOrClosePhone', 'export_index': 78584, 'params': (('BoolProperty', 'bShow'),)}, {'owner': 'TGWithCross', 'name': 'OnlineRequest_OpenOrCloseMic', 'export_index': 78586, 'params': (('BoolProperty', 'bShow'),)}, {'owner': 'TGWithCross', 'name': 'OnlineRequest_SetSpeakMode', 'export_index': 78588, 'params': (('ByteProperty', 'CurSpeakMode'),)}, {'owner': 'TGWithCross', 'name': 'OnlineRequest_OpenQTalkClient', 'export_index': 78590, 'params': (('BoolProperty', 'ReturnValue'),)}, {'owner': 'TGWithCross', 'name': 'OnlineRequest_FindTeamRoomName', 'export_index': 78594, 'params': (('StrProperty', 'RoomID'), ('StrProperty', 'subRoomID'), ('StrProperty', 'lastRoomID'))}, {'owner': 'TGWithCross', 'name': 'OnlineRequest_MaskUser', 'export_index': 78598, 'params': (('StrProperty', 'strUin'), ('StrProperty', 'RoomID'), ('BoolProperty', 'bMask'))}, {'owner': 'TGWithCross', 'name': 'OnlineRequest_GetUserMaskStatus', 'export_index': 78601, 'params': (('StrProperty', 'strUin'), ('StrProperty', 'strNickName'))}, {'owner': 'TGWithCross', 'name': 'OnlineRequest_SyncSetting', 'export_index': 78607, 'params': (('FloatProperty', 'fSoundsValue'), ('FloatProperty', 'fMicValue'), ('BoolProperty', 'bFreeTalk'), ('StrProperty', 'strKey'), ('BoolProperty', 'bGetSetting'))}, {'owner': 'TGWithCross', 'name': 'OnlineRequest_UnLoadCross', 'export_index': 78608, 'params': ()}, {'owner': 'TGWithCross', 'name': 'OnlineRequest_FocusKeyUp', 'export_index': 78609, 'params': ()}, {'owner': 'TGWithCross', 'name': 'OnlineRequest_GetCurrentQTRoom', 'export_index': 78610, 'params': ()})
V139_WIRE_BINDINGS = ({'owner': 'TGOnlineClient', 'name': 'OnlineRequest_CreateAccount', 'cmd': 40962, 'status': 'CURRENT_BRANCH', 'source': 'current v138 request handler', 'implemented': True}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_GetFriendStatus', 'cmd': 41731, 'status': 'CURRENT_BRANCH', 'source': 'current v138 request handler', 'implemented': True}, {'owner': 'TGOnlineMultiGameLobby', 'name': 'OnlineRequest_QueryRoomList', 'cmd': 41216, 'status': 'CURRENT_BRANCH', 'source': 'live room-list path', 'implemented': True}, {'owner': 'TGOnlineMultiGameLobby', 'name': 'OnlineRequest_ChannelList', 'cmd': 41266, 'status': 'CURRENT_BRANCH', 'source': 'live channel-list path', 'implemented': True}, {'owner': 'TGOnlineMultiGameLobby', 'name': 'OnlineRequest_MainChannelList', 'cmd': 41813, 'status': 'CURRENT_BRANCH', 'source': 'live main-channel path', 'implemented': True}, {'owner': 'TGOnlineMultiGameRoom', 'name': 'OnlineRequest_EnterRoomByRoomId', 'cmd': 41220, 'status': 'CURRENT_BRANCH', 'source': 'r11 shared-room A104/A105/A106 path', 'implemented': True}, {'owner': 'TGOnlineMultiGameRoom', 'name': 'OnlineRequest_CreateRoom', 'cmd': 41226, 'status': 'CURRENT_BRANCH', 'source': 'current creator-room path', 'implemented': True}, {'owner': 'TGOnlineMultiGameRoom', 'name': 'OnlineRequest_LeaveRoom', 'cmd': 41223, 'status': 'CURRENT_PARTIAL', 'source': 'live A107; v138 callback-schema work', 'implemented': True}, {'owner': 'TGOnlineMultiGameRoom', 'name': 'OnlineRequest_ChangeCamp', 'cmd': 41229, 'status': 'CURRENT_BRANCH', 'source': 'live A10D path', 'implemented': True}, {'owner': 'TGOnlineMultiGameRoom', 'name': 'OnlineRequest_SetReady', 'cmd': 41232, 'status': 'CURRENT_PARTIAL', 'source': 'current adjacent-family implementation', 'implemented': True}, {'owner': 'TGOnlineMultiGameRoom', 'name': 'OnlineRequest_StartMatch', 'cmd': 41235, 'status': 'CURRENT_BRANCH', 'source': 'live start-match path', 'implemented': True}, {'owner': 'TGOnlineMultiGameRoom', 'name': 'OnlineRequest_JoinMatch', 'cmd': 41237, 'status': 'CURRENT_PARTIAL', 'source': 'live A115 + v26 recovered full A116 DSInfo response', 'implemented': True}, {'owner': 'TGOnlineMultiGameRoom', 'name': 'OnlineRequest_QuitMatch', 'cmd': 41239, 'status': 'CURRENT_PARTIAL', 'source': 'live request; handler still incomplete', 'implemented': True}, {'owner': 'TGOnlineMultiGameRoom', 'name': 'OnlineRequest_SetInMatch', 'cmd': 41244, 'status': 'CURRENT_BRANCH', 'source': 'live post-DS path', 'implemented': True}, {'owner': 'TGOnlineMultiGameRoom', 'name': 'OnlineRequest_SetGameSettings', 'cmd': 41246, 'status': 'CURRENT_BRANCH', 'source': 'live A11E PvE settings path', 'implemented': True}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_CheckNickName', 'cmd': 41284, 'status': 'PRIOR_RECOVERED', 'source': 'v106 nickname branch', 'implemented': False}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_ChangeLoginRole', 'cmd': 41286, 'status': 'PRIOR_RECOVERED', 'source': 'v106 role-change branch', 'implemented': False}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_DropProp', 'cmd': 41827, 'status': 'PRIOR_RECOVERED', 'source': 'v106 inventory/shop branch', 'implemented': False}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_UpdateCommodifyFile', 'cmd': 42243, 'status': 'PRIOR_RECOVERED', 'source': 'v106 shop branch', 'implemented': False}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_BuyCommodity', 'cmd': 42245, 'status': 'PRIOR_RECOVERED', 'source': 'v106 hardened shop branch', 'implemented': False}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_UpdateTPValue', 'cmd': 42254, 'status': 'PRIOR_RECOVERED', 'source': 'v106 AP/TP branch', 'implemented': False}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_ReqAddFriend', 'cmd': 41733, 'status': 'PRIOR_RECOVERED', 'source': 'v106 friends branch', 'implemented': False}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_DeleteFriend', 'cmd': 41737, 'status': 'PRIOR_RECOVERED', 'source': 'v106 friends branch', 'implemented': False}, {'owner': 'TGOnlineClient', 'name': 'OnlineRequest_ChatP2P', 'cmd': 41989, 'status': 'PRIOR_RECOVERED', 'source': 'v106 private-chat branch', 'implemented': False}, {'owner': 'TGOnlineActivity', 'name': 'OnlineRequest_ReqCalendar', 'cmd': 49429, 'status': 'PRIOR_RECOVERED', 'source': 'v106 calendar/daily-login branch', 'implemented': False}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_CreateTeam', 'cmd': 42497, 'status': 'PRIOR_RECOVERED', 'source': 'v106 clan/team branch', 'implemented': False}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_PublishRecruit', 'cmd': 42499, 'status': 'PRIOR_RECOVERED', 'source': 'v106 clan/team branch', 'implemented': False}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_SearchTeamByName', 'cmd': 43521, 'status': 'PRIOR_RECOVERED', 'source': 'v106 clan/team branch', 'implemented': False}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_RecruitMemberList', 'cmd': 43523, 'status': 'PRIOR_RECOVERED', 'source': 'v106 clan/team branch', 'implemented': False}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_GetDetailTeamInfo', 'cmd': 43525, 'status': 'PRIOR_RECOVERED', 'source': 'v106 clan/team branch', 'implemented': False}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_GetMemberList', 'cmd': 43527, 'status': 'PRIOR_RECOVERED', 'source': 'v106 clan/team branch', 'implemented': False}, {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_CheckTeamName', 'cmd': 43778, 'status': 'PRIOR_RECOVERED', 'source': 'v106 clan/team branch', 'implemented': False})
V139_PROTOCOL_ONLY = {40960: ('Protocol.Login', 'CURRENT_BRANCH'), 40964: ('Protocol.Heartbeat', 'CURRENT_BRANCH'), 40968: ('Protocol.PropOperation', 'CURRENT_BRANCH'), 41888: ('Protocol.StartRoomAlloc', 'CURRENT_BRANCH'), 41891: ('Protocol.QuitRoomAlloc', 'MAPPED_ONLY'), 65285: ('Protocol.UnknownFF05', 'CURRENT_BRANCH')}
V139_CURRENT_HANDLER_IDS = frozenset((40960, 40962, 40964, 40968, 41216, 41223, 41226, 41229, 41232, 41235, 41239, 41244, 41246, 41266, 41731, 41813, 41888, 65285))



# PH clan metadata and October 5 captures; see docs/CLANS.md for live status.
V139_WIRE_BINDINGS = tuple(
    b for b in V139_WIRE_BINDINGS
    if (b["owner"], b["name"]) not in {('TGOnlineTeamRoom', 'OnlineRequest_TeamIntroduction'), ('TGOnlineTeamRoom', 'OnlineRequest_GetOtherTeamInfo'), ('TGOnlineTeamRoom', 'OnlineRequest_ApproveJoinResult'), ('TGOnlineTeamRoom', 'OnlineRequest_FireMember'), ('TGOnlineTeamRoom', 'OnlineRequest_ApproveList'), ('TGOnlineTeamRoom', 'OnlineRequest_CreateTeam'), ('TGOnlineTeamRoom', 'OnlineRequest_GetDetailTeamInfo'), ('TGOnlineTeamRoom', 'OnlineRequest_QuitTeam'), ('TGOnlineTeamRoom', 'OnlineRequest_GetMemberList'), ('TGOnlineTeamRoom', 'OnlineRequest_ApplyToJoinTeam'), ('TGOnlineTeamRoom', 'OnlineRequest_SearchTeamByName'), ('TGOnlineTeamRoom', 'OnlineRequest_CheckTeamName')}
)
V139_WIRE_BINDINGS += (
    {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_CreateTeam', 'cmd': 45057, 'status': 'CURRENT_PARTIAL', 'source': 'PH proto_c2zn.tdr clan macro/structure metadata', 'implemented': True},
    {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_SearchTeamByName', 'cmd': 45061, 'status': 'CURRENT_PARTIAL', 'source': 'PH proto_c2zn.tdr clan macro/structure metadata', 'implemented': True},
    {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_GetDetailTeamInfo', 'cmd': 45065, 'status': 'CURRENT_PARTIAL', 'source': 'PH proto_c2zn.tdr clan macro/structure metadata', 'implemented': True},
    {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_GetMemberList', 'cmd': 45067, 'status': 'CURRENT_PARTIAL', 'source': 'PH proto_c2zn.tdr clan macro/structure metadata', 'implemented': True},
    {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_GetOtherTeamInfo', 'cmd': 45069, 'status': 'CURRENT_PARTIAL', 'source': 'PH proto_c2zn.tdr clan macro/structure metadata', 'implemented': True},
    {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_CheckTeamName', 'cmd': 45071, 'status': 'CURRENT_PARTIAL', 'source': 'PH proto_c2zn.tdr clan macro/structure metadata', 'implemented': True},
    {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_ApplyToJoinTeam', 'cmd': 45075, 'status': 'CURRENT_PARTIAL', 'source': 'PH proto_c2zn.tdr clan macro/structure metadata', 'implemented': True},
    {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_ApproveList', 'cmd': 45077, 'status': 'CURRENT_PARTIAL', 'source': 'PH proto_c2zn.tdr clan macro/structure metadata', 'implemented': True},
    {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_ApproveJoinResult', 'cmd': 45081, 'status': 'CURRENT_PARTIAL', 'source': 'PH proto_c2zn.tdr clan macro/structure metadata', 'implemented': True},
    {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_FireMember', 'cmd': 45086, 'status': 'CURRENT_PARTIAL', 'source': 'PH proto_c2zn.tdr clan macro/structure metadata', 'implemented': True},
    {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_QuitTeam', 'cmd': 45092, 'status': 'CURRENT_PARTIAL', 'source': 'PH proto_c2zn.tdr clan macro/structure metadata', 'implemented': True},
    {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_TeamIntroduction', 'cmd': 45184, 'status': 'CURRENT_PARTIAL', 'source': 'PH proto_c2zn.tdr clan macro/structure metadata', 'implemented': True},
    {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_ConfirmJoin', 'cmd': 45079, 'status': 'CURRENT_PARTIAL', 'source': 'PH proto_c2zn.tdr clan metadata', 'implemented': True},
    {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_InvitePlayerJoin', 'cmd': 45099, 'status': 'CURRENT_PARTIAL', 'source': 'PH proto_c2zn.tdr clan metadata', 'implemented': True},
    {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_PromotionMember', 'cmd': 45088, 'status': 'CURRENT_PARTIAL', 'source': 'PH proto_c2zn.tdr clan metadata', 'implemented': True},
    {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_DemotionMember', 'cmd': 45090, 'status': 'CURRENT_PARTIAL', 'source': 'PH proto_c2zn.tdr clan metadata', 'implemented': True},
    {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_DissolveTeam', 'cmd': 0xB039, 'status': 'CURRENT_PARTIAL', 'source': 'October 5 PH capture and TDR schema', 'implemented': True},
    {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_ExtendTeam', 'cmd': 0xB025, 'status': 'CURRENT_PARTIAL', 'source': 'October 5 PH capture + metalib', 'implemented': True},
    {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_GetBulletin', 'cmd': 0xB02D, 'status': 'CURRENT_PARTIAL', 'source': 'October 5 PH capture + metalib', 'implemented': True},
    {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_SetBulletin', 'cmd': 0xB02F, 'status': 'CURRENT_PARTIAL', 'source': 'October 5 PH capture + metalib', 'implemented': True},
    {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_BuyBadge', 'cmd': 0xB04A, 'status': 'CURRENT_PARTIAL', 'source': 'October 5 PH capture + metalib', 'implemented': True},
    {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_SetBadge', 'cmd': 0xB04E, 'status': 'CURRENT_PARTIAL', 'source': 'PH metalib; badge setting confirmed in client', 'implemented': True},
    {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_GetBadgeList', 'cmd': 0xB050, 'status': 'CURRENT_PARTIAL', 'source': 'October 5 PH capture + metalib', 'implemented': True},
    {'owner': 'TGOnlineTeamRoom', 'name': 'OnlineRequest_GetTeamMemberGroupList', 'cmd': 0xB08A, 'status': 'CURRENT_PARTIAL', 'source': 'October 5 PH capture + metalib', 'implemented': True},
)

def _v139_sig(spec):
    params = ", ".join(
        f"{ptype} {pname}" for ptype, pname in spec.get("params", ())
    )
    return f"{spec['owner']}.{spec['name']}({params})"


def _v139_build_registry():
    if len(V139_UTGAME_REQUEST_CATALOG) != 318:
        raise RuntimeError(
            "v139 catalog corruption: expected 318 request exports, got "
            f"{len(V139_UTGAME_REQUEST_CATALOG)}"
        )

    by_key = {}
    by_export = {}

    for spec in V139_UTGAME_REQUEST_CATALOG:
        key = (spec["owner"], spec["name"])
        exp = int(spec["export_index"])

        if key in by_key:
            raise RuntimeError(f"v139 duplicate request key {key!r}")
        if exp in by_export:
            raise RuntimeError(f"v139 duplicate export index {exp}")

        by_key[key] = dict(spec)
        by_export[exp] = dict(spec)

    by_cmd = {}

    for binding in V139_WIRE_BINDINGS:
        key = (binding["owner"], binding["name"])
        if key not in by_key:
            raise RuntimeError(
                f"v139 binding points to missing UTGame request {key!r}"
            )

        cmd = int(binding["cmd"]) & 0xFFFF
        if cmd in by_cmd:
            raise RuntimeError(
                f"v139 duplicate wire ID 0x{cmd:04X}"
            )

        merged = dict(by_key[key])
        merged.update(binding)
        by_cmd[cmd] = merged

    return {
        "by_key": by_key,
        "by_export": by_export,
        "by_cmd": by_cmd,
    }


V139_PROTOCOL_REGISTRY = _v139_build_registry()

# v165: active recovered social request family.
_V165_FRIEND_BINDINGS = (
    (0xA305, ("TGOnlineClient", "OnlineRequest_ReqAddFriend")),
    (0xA307, ("TGOnlineClient", "OnlineRequest_ResAddFriend")),
    (0xA309, ("TGOnlineClient", "OnlineRequest_DeleteFriend")),
    (0xA30F, ("TGOnlineClient", "OnlineRequest_QueryFriend")),
    (0xA405, ("TGOnlineClient", "OnlineRequest_ChatP2P")),
    (0xA33A, ("TGOnlineClient", "OnlineRequest_GetPlayerExps")),
)
for _v165_cmd, _v165_key in _V165_FRIEND_BINDINGS:
    _v165_base = V139_PROTOCOL_REGISTRY["by_key"].get(_v165_key)
    if _v165_base is not None:
        _v165_spec = dict(_v165_base)
        _v165_spec.update(
            {
                "cmd": _v165_cmd,
                "status": "CURRENT_PARTIAL",
                "source": "v165-current-main-friends-bootstrap",
                "implemented": True,
            }
        )
        V139_PROTOCOL_REGISTRY["by_cmd"][_v165_cmd] = _v165_spec
V139_CURRENT_HANDLER_IDS = frozenset(
    set(V139_CURRENT_HANDLER_IDS)
    | {cmd for cmd, _key in _V165_FRIEND_BINDINGS}
)


def _v139_lookup_wire(cmd):
    cmd = int(cmd) & 0xFFFF

    spec = V139_PROTOCOL_REGISTRY["by_cmd"].get(cmd)
    if spec is not None:
        return spec

    proto = V139_PROTOCOL_ONLY.get(cmd)
    if proto is None:
        return None

    return {
        "owner": "Protocol",
        "name": proto[0],
        "cmd": cmd,
        "status": proto[1],
        "source": "protocol-level/non-OnlineRequest",
        "implemented": cmd in V139_CURRENT_HANDLER_IDS,
        "params": (),
        "export_index": None,
    }


def _v139_protocol_boot_report():
    mapped = len(V139_PROTOCOL_REGISTRY["by_cmd"])
    implemented = sum(
        1 for x in V139_PROTOCOL_REGISTRY["by_cmd"].values()
        if x.get("implemented")
    )
    partial = sum(
        1 for x in V139_PROTOCOL_REGISTRY["by_cmd"].values()
        if "PARTIAL" in x.get("status", "")
    )
    unresolved = len(V139_UTGAME_REQUEST_CATALOG) - mapped

    print(
        "[PROTOCOL-v139] UTGame request exports: "
        f"{len(V139_UTGAME_REQUEST_CATALOG)}",
        flush=True,
    )
    print(
        "[PROTOCOL-v139] numeric IDs mapped={} | current handlers={} | "
        "partial={} | unresolved IDs={}".format(
            mapped, implemented, partial, unresolved
        ),
        flush=True,
    )
    print(
        "[PROTOCOL-v139] duplicate IDs=0 | catalog self-test=PASS | "
        "unknown requests=LOG-ONLY/no guessed reply",
        flush=True,
    )


def _v139_trace_c2zn_request(cmd, body, label):
    spec = _v139_lookup_wire(cmd)
    if spec is None:
        return

    export_index = spec.get("export_index")
    exp = f" export={export_index}" if export_index is not None else ""

    log(
        label,
        "[PROTO-v139] "
        f"cmd=0x{int(cmd)&0xFFFF:04X} "
        f"{_v139_sig(spec)} "
        f"status={spec.get('status')} "
        f"implemented={bool(spec.get('implemented'))}"
        f"{exp} body_len={len(body)}",
    )


def _v139_unhandled_text(cmd):
    spec = _v139_lookup_wire(cmd)
    if spec is None:
        return "unmapped-to-UTGame"

    return (
        f"mapped={_v139_sig(spec)} "
        f"status={spec.get('status')} "
        f"implemented={bool(spec.get('implemented'))}"
    )


def _v139_unresolved_catalog():
    mapped_keys = {
        (x["owner"], x["name"])
        for x in V139_PROTOCOL_REGISTRY["by_cmd"].values()
    }

    return tuple(
        x for x in V139_UTGAME_REQUEST_CATALOG
        if (x["owner"], x["name"]) not in mapped_keys
    )



# ---------------------------------------------------------------------------
# VERSION SERVER RESPONSE (port 9060)
# ---------------------------------------------------------------------------

RESP = bytearray(bytes.fromhex(
    "000000414355000700020020230100000000000000000001"
    "000000010001000000000018001900000001000000000000"
    "0009312e302e302e323400000000000001"
))

RESP[0:4] = len(RESP).to_bytes(4, "big")
RESP[22] = 0
RESP[23] = 0
RESP[26] = 0
RESP[27] = 0

VERSION_RESPONSE = bytes(RESP)


# ---------------------------------------------------------------------------
# AUTH / AP CRYPTO
# ---------------------------------------------------------------------------

P_PRIME = int(
    "BB2A43DF39322DAAC8C3B30C9F21E13F"
    "646B7234A846231038C087F3408A558D"
    "A8AA1912AE906DEF3E781E39FE172B20"
    "3A6B8452056B3C9CB21237CAC3F5AA1B",
    16
)

G = 2

IV = bytes.fromhex(
    "b83bca76c4fd6d3ba5964edeb300df6c"
)

PRIME_BYTES = P_PRIME.to_bytes(64, "big")

DEFAULT_PRIVATE_KEY_PATH = Path(__file__).resolve().with_name("PRIVATE.PEM")
PRIVATE_KEY_PATH = str(
    resolve_private_key_path(
        script_path=Path(__file__),
        argv=sys.argv[1:],
        env=os.environ,
        cwd=Path.cwd(),
    )
)


try:
    with open(PRIVATE_KEY_PATH, "rb") as f:
        RSA_PRIV = serialization.load_pem_private_key(
            f.read(),
            password=None
        )

    print(
        "[BOOT] Loaded RSA private key from",
        PRIVATE_KEY_PATH,
        flush=True
    )

except Exception as e:
    print(
        f"[BOOT] FAILED to load RSA private key: {e}",
        flush=True
    )
    print(
        "[BOOT] Hint: keep PRIVATE.PEM in server\\, set AF_PRIVATE_KEY, "
        "or pass --private-key <path>.",
        flush=True,
    )
    RSA_PRIV = None


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

_SERVER_LOGGER = build_logger()


def log(label, message, level=None):
    """Console-filtered logger with always-on DEBUG file capture."""
    return _SERVER_LOGGER.emit(
        label,
        str(message),
        level=level,
    )


log("BOOT", f"Persistent server log: {_SERVER_LOGGER.path}")


# ---------------------------------------------------------------------------
# Stable v143b dedicated-server spawner integration
# ---------------------------------------------------------------------------
# This adds only DS allocation/process lifecycle to the proven v143b backend.
# It does NOT include the later first-login/new-account/profile branches.
V143B_DS_CONFIG = SpawnerConfig.from_env()
V143B_DS_SPAWNER = None


def _v143b_init_spawner():
    """Create mutable DS runtime state only after strict preflight succeeds."""
    global V143B_DS_SPAWNER
    if V143B_DS_SPAWNER is None:
        V143B_DS_SPAWNER = DedicatedServerSpawner(V143B_DS_CONFIG, log_fn=log)
    return V143B_DS_SPAWNER


# ---------------------------------------------------------------------------
# r11 shared multiplayer room/session state
# ---------------------------------------------------------------------------
# r10 already made the DS/bridge process lifecycle multiplayer-safe.  The
# missing piece was the stock ZONE room layer: each connection still kept its
# own creator-only room dict, so another client could not see/join it.  r11
# restores a process-wide room registry and live ZONE session map. Room
# records are SQLite-backed; live sockets and dedicated-server processes remain
# runtime-only. Waiting rooms can be restored for unexpired sessions after a
# restart; active matches are removed because their DS process cannot resume.
# Account/progression data remains in PlayerDatabase. Match rooms still
# disappear when their final member leaves.
V150_ROOM_REGISTRY = RoomRegistry(db_path=PLAYER_DB_PATH)

_V150_ZONE_LOCK = threading.RLock()
_V150_ZONE_SESSIONS = {}  # uin -> {conn,key,label,role_state,nickname}
_V150_CONN_SEND_LOCKS = {}  # id(socket) -> RLock
SERVER_SHUTTING_DOWN = threading.Event()


def _v150_role_uin(role_state):
    return int((role_state or {}).get("uin") or 10001)


def _v150_role_nickname(role_state):
    # FIRST-NICKNAME-v12 controlled probe:
    # A NULL DB nickname is intentionally kept as an empty wire nickname for
    # the entire session.  v11 proved that startup's automatic A008 role-equip
    # later calls this helper and otherwise injects the historical LocalPlayer
    # fallback through a post-role A005.
    if bool((role_state or {}).get("v12_force_blank_nickname", False)):
        return ""
    uin = _v150_role_uin(role_state)
    explicit = str((role_state or {}).get("nickname") or "").strip()
    if explicit:
        return explicit[:31]
    return "LocalPlayer" if uin == 10001 else f"Player{uin}"[:31]


def _v150_conn_send_lock(conn):
    key = id(conn)
    with _V150_ZONE_LOCK:
        lock = _V150_CONN_SEND_LOCKS.get(key)
        if lock is None:
            lock = threading.RLock()
            _V150_CONN_SEND_LOCKS[key] = lock
        return lock


def _v150_register_zone_session(role_state, conn, key, label):
    if str(label).upper() != "ZONE" or not isinstance(role_state, dict) or not key:
        return None
    uin = _v150_role_uin(role_state)
    session = {
        "uin": uin,
        "nickname": _v150_role_nickname(role_state),
        "conn": conn,
        "key": bytes(key),
        "label": str(label),
        "role_state": role_state,
    }
    with _V150_ZONE_LOCK:
        _V150_ZONE_SESSIONS[uin] = session
        _v150_conn_send_lock(conn)
    return session


def _v150_unregister_zone_session(role_state, conn=None):
    if not isinstance(role_state, dict):
        return
    uin = _v150_role_uin(role_state)
    with _V150_ZONE_LOCK:
        current = _V150_ZONE_SESSIONS.get(uin)
        if current is not None and (conn is None or current.get("conn") is conn):
            _V150_ZONE_SESSIONS.pop(uin, None)
        if conn is not None:
            _V150_CONN_SEND_LOCKS.pop(id(conn), None)


def _v150_session_snapshot(uin):
    with _V150_ZONE_LOCK:
        s = _V150_ZONE_SESSIONS.get(int(uin))
        return dict(s) if s else None


def _v150_send_online(uin, app_plain, desc, tpdu_cmd=0):
    session = _v150_session_snapshot(uin)
    if not session:
        log("ROOM", f"r11 push skipped uin={int(uin)} offline desc={desc}")
        return False
    try:
        _v48_send_app(
            session["conn"],
            session["key"],
            app_plain,
            session.get("label") or "ZONE",
            desc,
            tpdu_cmd=tpdu_cmd,
        )
        return True
    except Exception as exc:
        log("ROOM", f"r11 push failed uin={int(uin)} desc={desc}: {type(exc).__name__}: {exc}")
        return False
def _v150_sync_role_states(room):
    """Refresh per-connection compatibility mirrors from the shared room."""
    if not isinstance(room, dict):
        return
    room_id = int(room["room_id"])
    by_uin = {int(m["uin"]): m for m in room.get("members") or []}
    with _V150_ZONE_LOCK:
        sessions = [dict(s) for u, s in _V150_ZONE_SESSIONS.items() if int(u) in by_uin]
    for s in sessions:
        rs = s.get("role_state")
        if not isinstance(rs, dict):
            continue
        member = by_uin[int(s["uin"])]
        rs["v79_created_match_room"] = room
        rs["v143b_ds_room_id"] = room_id
        rs["v83_in_match_room"] = True
        rs["v88_match_seat"] = int(member.get("seat_index", 0))
        rs["v88_match_camp"] = int(member.get("camp", 1))


def _v150_broadcast_room(room_id, app_plain, desc, exclude=(), tpdu_cmd=0):
    room = V150_ROOM_REGISTRY.get_room(int(room_id))
    if not room:
        return []
    excluded = {int(x) for x in exclude}
    sent = []
    for member in room.get("members") or []:
        uin = int(member["uin"])
        if uin in excluded:
            continue
        if _v150_send_online(uin, app_plain, desc, tpdu_cmd=tpdu_cmd):
            sent.append(uin)
    return sent
V143B_ZONE_ERR_NO_DS_CAPACITY = int(
    os.environ.get("AF_ZONE_ERR_NO_DS_CAPACITY", "0x8101"), 0
) & 0xFFFF


def _v143b_tdr_ipv4(host):
    """Convert dotted IPv4 to the byte order GameServerInfo.Ip expects."""
    packed = socket.inet_aton(str(host))
    return int.from_bytes(packed, "little")


# v177: transient friend room invitations; relationship remains in SQLite.
_V177_ROOM_INVITES = {}
_V177_INVITE_SEQUENCE = 0


def _v177_friend_location(uin):
    session = _v150_session_snapshot(uin)
    if session is None:
        return None, None, bytes(24)
    room = V150_ROOM_REGISTRY.room_for_player(uin)
    state = session.get('role_state') or {}
    main = int(state.get('main_channel_id') or 1)
    sub = int((room or {}).get('sub_channel_id') or state.get('sub_channel_id') or 1)
    address = (_v48_u32(main) + _v48_u32(sub)
               + _v48_u64((room or {}).get('room_id', 0))
               + _v48_u16((room or {}).get('display_id', 0))
               + _v48_u32((room or {}).get('mode_id', 0))
               + _v48_u16((room or {}).get('map_id', 0)))
    return session, room, address


def _v177_room_invitable(room):
    return (room is not None and not room.get('started')
            and int(room.get('fighter_count', 0)) < int(room.get('fighter_capacity', 0)))


def _v178_parse_trace_enter(body, role_state):
    if len(body) < 23:
        raise ValueError('truncated A120')
    room_id = struct.unpack_from('>Q', body)[0]
    password, _, off = _v79_read_lp_string(body, 8, 8)
    if off + 10 != len(body):
        raise ValueError('invalid A120 tail')
    kind, friend = struct.unpack_from('>HQ', body, off)
    actor = _v150_role_uin(role_state)
    _, room, _ = _v177_friend_location(friend)
    if not room or int(room['room_id']) != room_id:
        raise ValueError('friend moved out of requested room')
    if not FRIENDS_SERVICE.are_friends(actor, friend):
        raise ValueError('trace target is not a friend')
    invite_id = None
    if kind == 2:
        with _V150_ZONE_LOCK:
            invite_id = next((rid for rid, entry in _V177_ROOM_INVITES.items()
                if entry['sender'] == friend and entry['recipient'] == actor
                and int(entry['room']) == room_id
                and entry['expires'] > time.monotonic()), None)
        if invite_id is None or not _v177_room_invitable(room):
            raise ValueError('no valid invitation for requested room')
        # A bound room invitation authorizes entering its password-protected room.
        password = str(room.get('password') or '')
    elif kind != 1:
        raise ValueError('unsupported trace entry type')
    return dict(room_id=room_id, password=password, observer=False,
                tail=b'', invite_id=invite_id, inviter=friend)


def _v177_friend_action(conn, key, label, role_state, app):
    global _V177_INVITE_SEQUENCE
    cmd, body = app['cmd'], bytes(app['body'])
    actor = _v150_role_uin(role_state)
    target = 0
    response = None
    try:
        if cmd == 0xA317:
            if len(body) != 10:
                raise ValueError('A317 requires Type:u16 and FriendUin:u64')
            kind, target = struct.unpack('>HQ', body)
            session, room, address = _v177_friend_location(target)
            allowed = kind == 1 and FRIENDS_SERVICE.are_friends(actor, target)
            result = 0x8300 if allowed and session else (0x030C if not allowed else 0x0306)
            if result != 0x8300:
                address = bytes(24)
            response = _v62_build_server_app(TGAME_ZN_MAGIC, 0xA318,
                _v48_u64(target) + address + _v48_u16(result))
        elif cmd == 0xA313:
            if len(body) != 8:
                raise ValueError('A313 requires FriendUin:u64')
            target = struct.unpack('>Q', body)[0]
            identity = FRIENDS_SERVICE.get_player_identity(target)
            target_name = str((identity or {}).get('nickname') or '')
            sender_session, room, address = _v177_friend_location(actor)
            recipient_session, recipient_room, _ = _v177_friend_location(target)
            result = 0x0300
            if not FRIENDS_SERVICE.are_friends(actor, target):
                result = 0x030B
            elif recipient_session is None:
                result = 0x0306
            elif not _v177_room_invitable(room) or recipient_room is not None:
                result = 0x030F
            else:
                now = time.monotonic()
                with _V150_ZONE_LOCK:
                    for rid, entry in list(_V177_ROOM_INVITES.items()):
                        if entry['expires'] <= now:
                            del _V177_ROOM_INVITES[rid]
                    # Repeated outstanding invitations reuse their bound ID.
                    existing = next(((rid, entry) for rid, entry in _V177_ROOM_INVITES.items()
                        if entry['sender'] == actor and entry['recipient'] == target
                        and entry['room'] == room['room_id']), None)
                    if existing:
                        request_id = existing[0]
                    else:
                        if len(_V177_ROOM_INVITES) >= 4096:
                            raise ValueError('room invitation queue full')
                        _V177_INVITE_SEQUENCE = (_V177_INVITE_SEQUENCE + 1) & 0xFFFFFFFF or 1
                        while _V177_INVITE_SEQUENCE in _V177_ROOM_INVITES:
                            _V177_INVITE_SEQUENCE = (_V177_INVITE_SEQUENCE + 1) & 0xFFFFFFFF or 1
                        request_id = _V177_INVITE_SEQUENCE
                        _V177_ROOM_INVITES[request_id] = dict(sender=actor, recipient=target,
                            room=room['room_id'], expires=now+120)
                invite_address = address[:8] + _v150_pack_basic_match_room_info(room)
                packet = _v62_build_server_app(TGAME_ZN_MAGIC, 0xA314,
                    _v48_u32(request_id) + _v48_u64(actor)
                    + _v50_geo_tdr_string(_v150_role_nickname(role_state), 32) + invite_address)
                if _v150_send_online(target, packet, f'friend room invite id={request_id} from={actor}'):
                    return
                with _V150_ZONE_LOCK:
                    _V177_ROOM_INVITES.pop(request_id, None)
                result = 0x0306
            response = _v62_build_server_app(TGAME_ZN_MAGIC, 0xA316,
                _v50_geo_tdr_string(target_name, 32) + _v48_u16(result) + _v48_u32(0))
        elif cmd == 0xA315:
            if len(body) != 18:
                raise ValueError('A315 requires request ID, inviter UIN, result and reason')
            request_id, inviter, result, reason = struct.unpack('>IQHi', body)
            with _V150_ZONE_LOCK:
                pending = _V177_ROOM_INVITES.get(request_id)
                if (not pending or pending['sender'] != inviter or pending['recipient'] != actor
                        or pending['expires'] <= time.monotonic()):
                    raise ValueError('invalid or expired room invitation')
                if result not in (0x0309, 0x0308, 0x030F):
                    raise ValueError('invalid invitation decision')
                if result != 0x0309:
                    del _V177_ROOM_INVITES[request_id]
            # The stock client joins via its ordinary room-entry request; never
            # bypass capacity, password, started-match or room admission checks.
            _, current_room, _ = _v177_friend_location(inviter)
            if result == 0x0309 and (not _v177_room_invitable(current_room)
                    or current_room['room_id'] != pending['room']
                    or not FRIENDS_SERVICE.are_friends(actor, inviter)):
                result = 0x030F
            packet = _v62_build_server_app(TGAME_ZN_MAGIC, 0xA316,
                _v50_geo_tdr_string(_v150_role_nickname(role_state), 32)
                + _v48_u16(result) + _v48_i32(reason))
            _v150_send_online(inviter, packet, f'friend invite decision id={request_id} from={actor}')
            return
    except Exception as exc:
        log('SOCIAL', f'friend action cmd=0x{cmd:04X} actor={actor}: {type(exc).__name__}: {exc}')
        if cmd == 0xA317:
            response = _v62_build_server_app(TGAME_ZN_MAGIC, 0xA318,
                _v48_u64(target) + bytes(24) + _v48_u16(0x030C))
        elif cmd == 0xA313:
            response = _v62_build_server_app(TGAME_ZN_MAGIC, 0xA316,
                _v50_geo_tdr_string('', 32) + _v48_u16(0x0300) + _v48_u32(0))
    if response is not None:
        _v48_send_app(conn, key, response, label, f'friend action response cmd=0x{cmd:04X}')


def _v165_online_uins():
    with _V150_ZONE_LOCK:
        return {int(uin) for uin in _V150_ZONE_SESSIONS}


def _v165_deliver_pending_social(uin):
    uin = int(uin)
    invite_count = 0
    message_count = 0

    for req in FRIENDS_SERVICE.list_pending_friend_requests(uin):
        proposer = FRIENDS_SERVICE.get_player_identity(int(req["from_uin"]))
        if proposer is None:
            continue
        pkt = build_friend_invite(
            request_id=int(req["request_id"]),
            proposer_uin=int(req["from_uin"]),
            proposer_name=str(proposer["nickname"]),
            remark=str(req.get("remark") or ""),
            msg_id=int(req.get("msg_id") or req["request_id"]),
        )
        if _v150_send_online(
            uin,
            pkt,
            "ZN2C_REQ_ADDFRIEND v165-real "
            f"request_id={int(req['request_id'])} "
            f"from={proposer['nickname']}({int(req['from_uin'])})",
        ):
            invite_count += 1

    for msg in FRIENDS_SERVICE.list_pending_private_messages(uin):
        pkt = build_chat_p2p_notify(
            int(msg["chat_type"]),
            str(msg["message"]),
            sender_uin=int(msg["sender_uin"]),
            sender_name=str(msg.get("sender_nickname") or ""),
        )
        if _v150_send_online(
            uin,
            pkt,
            "ZN2C_NTF_CHATP2P v165-real "
            f"offline-id={int(msg['message_id'])} "
            f"from={msg.get('sender_nickname')!r}({int(msg['sender_uin'])})",
        ):
            FRIENDS_SERVICE.mark_private_message_delivered(int(msg["message_id"]))
            message_count += 1

    return invite_count, message_count


def _v165_seed_friend_rows(uin, friends):
    sent = 0
    for friend in friends or []:
        pkt = build_add_friend_result(
            friend_uin=int(friend["uin"]),
            friend_name=str(friend["nickname"]),
            result=0x8301,  # SNS_ADDFRID_AGREE
            msg_id=0,
        )
        if _v150_send_online(
            int(uin),
            pkt,
            "ZN2C_RES_ADDFRIEND v168-seed-agree "
            f"friend={friend['nickname']}({int(friend['uin'])})",
        ):
            sent += 1
    return sent

def _v143b_reserve_room_ds(role_state, create_req):
    if not V143B_DS_CONFIG.enabled:
        return None

    owner_uin = int(role_state.get("uin") or 10001)
    use_client_map = os.environ.get("AF_DS_USE_CLIENT_MAP", "1").strip().lower() in (
        "1", "true", "yes", "on"
    )
    client_map = str(create_req.get("map_string") or "").strip()
    if use_client_map:
        map_name = client_map or None
    else:
        map_name = V143B_DS_CONFIG.default_map
    max_players = max(2, int(create_req.get("fighter_capacity") or 0))

    allocation = V143B_DS_SPAWNER.reserve_lobby(
        owner_id=owner_uin,
        owner_nickname=_v150_role_nickname(role_state),
        map_name=map_name,
        max_players=max_players,
        mode_id=int(create_req.get("mode_id", 0x00002001)),
        map_id=int(create_req.get("map_id", 0x002F)),
        sub_mode_id=int(create_req.get("sub_mode_id", 0x00001001)),
        room_flags=int(create_req.get("flags", 0x00003008)),
    )
    # r8: reservation is bookkeeping only. Do NOT start the bridge or AFDEV
    # during A10A. The bridge is armed only when match handoff is requested.
    role_state["v143b_ds_room_id"] = allocation.room_id
    return allocation


def _v143b_release_room_ds(room, reason):
    if not V143B_DS_CONFIG.enabled or not isinstance(room, dict):
        return
    room_id = room.get("room_id")
    if room_id is not None:
        V143B_DS_SPAWNER.release_lobby(int(room_id), reason=reason)


def _v143b_room_id(role_state, room=None):
    if isinstance(room, dict) and room.get("room_id") is not None:
        return int(room["room_id"])
    rid = role_state.get("v143b_ds_room_id") if isinstance(role_state, dict) else None
    return int(rid) if rid is not None else None


def _v143b_begin_match_players(role_state, room=None):
    if not V143B_DS_CONFIG.enabled:
        return None
    room_id = _v143b_room_id(role_state, room)
    if room_id is None:
        return None
    uin = int(role_state.get("uin") or 10001)
    return V143B_DS_SPAWNER.begin_match(room_id, starter_uin=uin)


def _v143b_mark_player_in_match(role_state, room=None):
    if not V143B_DS_CONFIG.enabled:
        return None
    room_id = _v143b_room_id(role_state, room)
    if room_id is None:
        return None
    uin = int(role_state.get("uin") or 10001)
    return V143B_DS_SPAWNER.mark_player_in_match(room_id, uin)


def _v143b_quit_match_player(role_state, room, reason):
    if not V143B_DS_CONFIG.enabled:
        return None
    room_id = _v143b_room_id(role_state, room)
    if room_id is None:
        return None
    uin = int(role_state.get("uin") or 10001)
    return V143B_DS_SPAWNER.quit_match_player(room_id, uin, reason=reason)


def _v143b_clear_player_handoff_state(role_state):
    """Clear per-player state that must be fresh for the next A11A handoff."""
    if not isinstance(role_state, dict):
        return
    role_state.pop("v143b_ds_endpoint", None)
    role_state.pop("v132_pve_afdev_handoff_sent", None)
    role_state.pop("v132_pve_afdev_handoff_reason", None)
    role_state.pop("v132_pve_afdev_handoff_at", None)
    role_state.pop("v134_ready_ntf_sent", None)
    role_state["v132_match_ready"] = False


def _v143b_reset_room_after_round(room_id, reason):
    """Reset logical room + all live member handoff guards after a round ends."""
    room_id = int(room_id)
    room = V150_ROOM_REGISTRY.reset_round_state(room_id)
    _v150_sync_role_states(room)

    member_uins = {int(m["uin"]) for m in (room.get("members") or [])}
    with _V150_ZONE_LOCK:
        sessions = [
            dict(session)
            for uin, session in _V150_ZONE_SESSIONS.items()
            if int(uin) in member_uins
        ]
    for session in sessions:
        _v143b_clear_player_handoff_state(session.get("role_state"))

    log(
        "DS-REJOIN",
        f"round reset room={room_id} reason={reason}; "
        f"members={sorted(member_uins)} started=False ready=False "
        "handoff guards cleared",
    )
    return room


def _v143b_remove_room_player(
    role_state,
    room,
    reason,
    *,
    authoritative_new_owner=None,
):
    if not V143B_DS_CONFIG.enabled:
        return None
    room_id = _v143b_room_id(role_state, room)
    if room_id is None:
        return None
    uin = int(role_state.get("uin") or 10001)
    return V143B_DS_SPAWNER.remove_room_player(
        room_id,
        uin,
        reason=reason,
        authoritative_new_owner=authoritative_new_owner,
    )


# ---------------------------------------------------------------------------
# Socket helpers
# ---------------------------------------------------------------------------

def recv_exact(conn, size, timeout=10.0):
    conn.settimeout(timeout)

    data = bytearray()

    while len(data) < size:
        try:
            chunk = conn.recv(size - len(data))
        except socket.timeout:
            break

        if not chunk:
            break

        data.extend(chunk)

    return bytes(data)


# ---------------------------------------------------------------------------
# Normal PKCS#7 AES used by the initial AUTH handshake
# ---------------------------------------------------------------------------

def aes_cbc_encrypt_pkcs7(key, plaintext):
    padlen = 16 - (len(plaintext) % 16)

    padded = (
        plaintext +
        bytes([padlen]) * padlen
    )

    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(IV),
        backend=default_backend()
    )

    enc = cipher.encryptor()

    return enc.update(padded) + enc.finalize()


# ---------------------------------------------------------------------------
# AP message crypto
#
# TCLS uses its own padding layout here.
#
# Let:
#
#     r = plaintext_length % 16
#
# If r == 0:
#
#     r = 16
#
# All complete blocks except the last r plaintext bytes are written normally.
#
# The remaining r bytes go into the beginning of a final 32-byte area:
#
#     final[0:r] = tail
#     final[16]  = 16-r
#
# Everything else in that 32-byte area is zero.
# ---------------------------------------------------------------------------

def ap_encrypt(key, plaintext):
    if not plaintext:
        raise ValueError("cannot AP-encrypt empty plaintext")

    r = len(plaintext) & 0x0F

    if r == 0:
        r = 16

    prefix_len = len(plaintext) - r

    prefix = plaintext[:prefix_len]
    tail = plaintext[prefix_len:]

    final = bytearray(32)

    final[0:r] = tail

    # TCLS custom padding marker
    final[16] = 16 - r

    padded = prefix + bytes(final)

    if len(padded) % 16 != 0:
        raise ValueError("internal AP padding error")

    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(IV),
        backend=default_backend()
    )

    enc = cipher.encryptor()

    return enc.update(padded) + enc.finalize()


def ap_decrypt(key, ciphertext):
    if len(ciphertext) < 32:
        raise ValueError(
            f"AP ciphertext too short: {len(ciphertext)}"
        )

    if len(ciphertext) % 16 != 0:
        raise ValueError(
            f"AP ciphertext not block aligned: {len(ciphertext)}"
        )

    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(IV),
        backend=default_backend()
    )

    dec = cipher.decryptor()

    padded = (
        dec.update(ciphertext) +
        dec.finalize()
    )

    # In the last 32-byte special block,
    # offset 16 contains 16-r.
    marker = padded[-16]

    if marker > 15:
        raise ValueError(
            f"invalid AP padding marker: {marker}"
        )

    logical_len = (
        len(padded) -
        (16 + marker)
    )

    if logical_len < 0:
        raise ValueError(
            "invalid AP logical length"
        )

    return padded[:logical_len]


# ---------------------------------------------------------------------------
# AP HNNW frame
# ---------------------------------------------------------------------------

def recv_ap_frame(conn, timeout=15.0):
    header = recv_exact(
        conn,
        6,
        timeout=timeout
    )

    if not header:
        return None

    if len(header) != 6:
        raise ValueError(
            f"short AP header: {len(header)}B"
        )

    if header[:4] != b"HNNW":
        raise ValueError(
            f"wrong AP sync word: {header[:4]!r}"
        )

    body_len = int.from_bytes(
        header[4:6],
        "big"
    )

    ciphertext = recv_exact(
        conn,
        body_len,
        timeout=timeout
    )

    if len(ciphertext) != body_len:
        raise ValueError(
            f"short AP body: "
            f"{len(ciphertext)}/{body_len}B"
        )

    return ciphertext


def build_ap_frame(key, plaintext):
    encrypted = ap_encrypt(
        key,
        plaintext
    )

    return (
        b"HNNW" +
        len(encrypted).to_bytes(2, "big") +
        encrypted
    )


# ---------------------------------------------------------------------------
# Generic TDR header
#
#   u16 msgsize
#   u16 version
#   u32 seqno
#   u16 cmd
#
# msgsize = number of bytes AFTER this 10-byte header.
# ---------------------------------------------------------------------------

def parse_tdr_header(data):
    if len(data) < 10:
        raise ValueError(
            f"TDR message too short: {len(data)}B"
        )

    msgsize = int.from_bytes(
        data[0:2],
        "big"
    )

    version = int.from_bytes(
        data[2:4],
        "big"
    )

    seqno = int.from_bytes(
        data[4:8],
        "big"
    )

    cmd = int.from_bytes(
        data[8:10],
        "big"
    )

    return {
        "msgsize": msgsize,
        "version": version,
        "seqno": seqno,
        "cmd": cmd,
        "body": data[10:]
    }


# ---------------------------------------------------------------------------
# AP_CMD_RESULT = cmd 4
#
# Body:
#
#   u32 error_code
#   u32 oas_error_code
#
#   u32 error_message_length
#   char error_message[length]
#
#   u32 uid
#   u32 timestamp
#
#   u16 ticket_size
#   byte ticket[ticket_size]
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# r12 LOCAL MULTI-CLIENT TEST IDENTITY
# ---------------------------------------------------------------------------

_R12_UID_LOCK = threading.Lock()
_R12_UID_BY_CLIENT_PID = {}
_R12_LOGIN_BY_UID = {}
_R12_NEXT_UID = 10001

# One SQLite file remains authoritative for accounts and game persistence.
PLAYER_DB = PlayerDatabase()
FRIENDS_SERVICE = FriendsService(PLAYER_DB.db_path)
CLAN_DB = ClanDatabase(PLAYER_DB.db_path)
CLAN_SERVICE = ClanService(
    CLAN_DB, is_online=lambda uin: _v150_session_snapshot(uin) is not None,
    send_notification=lambda uin, cmd, body: _v150_send_online(
        uin, _v62_build_server_app(TGAME_ZN_MAGIC, cmd, body),
        f'CLAN notification cmd=0x{cmd:04X} uin={uin}'),
)


def _r12_uid_for_client_pid(pid):
    global _R12_NEXT_UID
    pid_key = int(pid) if pid is not None else None
    with _R12_UID_LOCK:
        if pid_key is not None and pid_key in _R12_UID_BY_CLIENT_PID:
            return int(_R12_UID_BY_CLIENT_PID[pid_key])
        uid = int(_R12_NEXT_UID)
        _R12_NEXT_UID += 1
        if pid_key is not None:
            _R12_UID_BY_CLIENT_PID[pid_key] = uid
        return uid


def _r12_uid_for_login(pid, login_name):
    """Resolve the AP login to a stable SQLite-backed UIN.

    PID remains only a live-process cache. Relaunching the same login returns
    the same UIN instead of allocating another process-local identity.
    """
    login_name = str(login_name or "").strip()
    if not login_name:
        return _r12_uid_for_client_pid(pid)
    uid = int(PLAYER_DB.resolve_identity(login_name))
    pid_key = int(pid) if pid is not None else None
    with _R12_UID_LOCK:
        if pid_key is not None:
            _R12_UID_BY_CLIENT_PID[pid_key] = uid
        _R12_LOGIN_BY_UID[uid] = login_name
    return uid


def _r12_remember_login_for_uid(uid, login_name):
    login_name = str(login_name or "").strip()
    if not login_name:
        return None
    with _R12_UID_LOCK:
        _R12_LOGIN_BY_UID[int(uid)] = login_name
    return login_name


def _r12_login_for_uid(uid):
    with _R12_UID_LOCK:
        return _R12_LOGIN_BY_UID.get(int(uid))


def _r12_load_persisted_nickname(uid):
    login_name = _r12_login_for_uid(uid) or PLAYER_DB.login_for_uin(int(uid))
    if not login_name:
        return None, None
    try:
        nickname = PLAYER_DB.load_nickname(int(uid))
    except Exception as exc:
        log(
            "NICKNAME",
            f"SQLite nickname load warning uid={int(uid)} "
            f"login={login_name!r}: {type(exc).__name__}: {exc}",
        )
        return login_name, None
    return login_name, nickname


# ---------------------------------------------------------------------------
# Initial AUTH handshake
# ---------------------------------------------------------------------------

def build_auth_response(request_bytes):
    if RSA_PRIV is None:
        raise RuntimeError(
            "RSA private key is not loaded"
        )

    if len(request_bytes) != 214:
        raise ValueError(
            f"AUTH request should be 214B, "
            f"got {len(request_bytes)}B"
        )

    # The entire 128 bytes at 86:214 are ONE RSA-1024 ciphertext.
    rsa_ciphertext = request_bytes[86:214]

    plain = RSA_PRIV.decrypt(
        rsa_ciphertext,
        padding.PKCS1v15()
    )

    print(
        f"[AUTH] RSA plaintext len={len(plain)}",
        flush=True
    )

    if DEBUG_AUTH_HEX:
        print(
            f"[AUTH] RSA plaintext={plain.hex()}",
            flush=True
        )

    hello = parse_client_dh_plaintext(
        plain,
        prime=P_PRIME,
        width=64,
    )
    nonce = hello.nonce
    client_pub = hello.client_public
    client_pub_bytes = hello.canonical_public

    print(
        f"[AUTH] nonce=0x{nonce:08x}",
        flush=True
    )

    if len(hello.wire_public) != 64:
        print(
            f"[AUTH] client DH public wire length="
            f"{len(hello.wire_public)}B; normalized to 64B",
            flush=True
        )

    if DEBUG_AUTH_HEX:
        print(
            f"[AUTH] client_pub="
            f"{client_pub_bytes.hex()}",
            flush=True
        )

    # ------------------------------------------------------------------
    # v136 AUTH stability fix
    #
    # The PH TCLS client serializes the DH shared integer as a minimal-length
    # big-endian bignum before deriving the AP AES key.  Our older server
    # always MD5-hashed a fixed 64-byte buffer.
    #
    # Those are identical for normal 64-byte shared values, but differ when
    # the shared secret begins with 0x00.  That produced the intermittent
    # symptom:
    #
    #     AUTH ACK sent
    #     client sent no AP request
    #     UI: AP account failed
    #
    # Rather than changing the already-proven working KDF path, reject that
    # rare DH server exponent and draw another one until the shared secret is
    # naturally 64 bytes.  Then both serializations are byte-identical.
    # ------------------------------------------------------------------
    for dh_attempt in range(1, 65):
        server_priv = (
            int.from_bytes(
                os.urandom(64),
                "big"
            ) % (P_PRIME - 2)
        ) + 1

        server_pub = pow(
            G,
            server_priv,
            P_PRIME
        )

        server_pub_bytes = (
            server_pub.to_bytes(
                64,
                "big"
            )
        )

        shared = pow(
            client_pub,
            server_priv,
            P_PRIME
        )

        shared_bytes = shared.to_bytes(
            64,
            "big"
        )

        if shared_bytes[0] != 0:
            if dh_attempt > 1:
                print(
                    f"[AUTH] v136 DH retry accepted on attempt "
                    f"{dh_attempt}; avoided leading-zero shared secret",
                    flush=True
                )
            break

        print(
            f"[AUTH] v136 DH attempt {dh_attempt}: "
            "shared secret begins with 00; regenerating server exponent",
            flush=True
        )
    else:
        raise RuntimeError(
            "unable to generate non-leading-zero DH shared secret "
            "after 64 attempts"
        )

    # TCLS key derivation on the now-unambiguous 64-byte representation:
    #
    # AES-128 key = MD5(DH shared secret bytes)
    #
    aes_key = hashlib.md5(
        shared_bytes
    ).digest()

    print(
        f"[AUTH] server_pub="
        f"{server_pub_bytes.hex()}",
        flush=True
    )

    print(
        "[AUTH] DH shared secret established; shared and AES key material redacted",
        flush=True,
    )

    # Client requires nonce + 1.
    ack_seq = (
        nonce + 1
    ) & 0xFFFFFFFF

    ack_plain = (
        ack_seq.to_bytes(4, "big") +
        b"\x00" * 16
    )

    print(
        f"[AUTH] ack_seq="
        f"0x{ack_seq:08x}",
        flush=True
    )

    print(
        f"[AUTH] ack_plain="
        f"{ack_plain.hex()}",
        flush=True
    )

    # The initial handshake uses normal PKCS#7,
    # unlike subsequent AP messages.
    field_E = aes_cbc_encrypt_pkcs7(
        aes_key,
        ack_plain
    )

    print(
        f"[AUTH] field_E="
        f"{field_E.hex()}",
        flush=True
    )

    field_D = server_pub_bytes

    # SHA1 RSA signature over:
    #
    #     server_DH_public || encrypted_ACK
    #
    sig = RSA_PRIV.sign(
        field_D + field_E,
        padding.PKCS1v15(),
        hashes.SHA1()
    )

    if len(sig) != 128:
        raise ValueError(
            f"unexpected RSA signature size: "
            f"{len(sig)}"
        )

    body = (
        (0).to_bytes(2, "big") +
        (0).to_bytes(4, "big") +
        len(field_E).to_bytes(2, "big") +
        len(field_D).to_bytes(1, "big") +
        field_D +
        field_E +
        sig
    )

    response = (
        b"HNNW" +
        len(body).to_bytes(2, "big") +

        # version
        (1).to_bytes(2, "big") +

        # status
        (0).to_bytes(4, "big") +

        # cmd = 2
        (2).to_bytes(2, "big") +

        body
    )

    print(
        f"[AUTH] response={len(response)}B "
        f"header={response[:14].hex()}",
        flush=True
    )

    return response, aes_key


# ---------------------------------------------------------------------------
# VERSION handler
# ---------------------------------------------------------------------------

def handle_version(conn, addr):
    try:
        request = recv_exact(
            conn,
            65,
            timeout=6.0
        )

        pid, pname = identify_peer_process(addr, conn.getsockname()[1])
        owner = f" OWNER={pname or '?'} PID={pid}" if pid is not None else " OWNER=<unresolved>"
        uin_hint = 0
        if len(request) >= 53:
            try:
                uin_hint = int.from_bytes(request[49:53], "big")
            except Exception:
                uin_hint = 0
        log(
            "VERSION",
            f"Connected from {addr}{owner} ({len(request)}B) uin_hint={uin_hint}"
        )

        if len(request) != 65:
            log("VERSION", f"Bad request length: {len(request)}")
            return

        log("VERSION", f"RX {_short_hex(request)}")

        # IMPORTANT:
        # Echo THIS request, because after START it contains
        # the UID and selected World/Server ID.
        response = bytearray(request)

        # Length
        response[0:4] = len(response).to_bytes(4, "big")

        # Success/status fields
        response[22] = 0
        response[23] = 0
        response[26] = 0
        response[27] = 0

        response = bytes(response)

        conn.sendall(response)

        log(
            "VERSION",
            f"TX {len(response)}B: {_short_hex(response)}"
        )

    except Exception as e:
        log("VERSION", f"error: {e}")

    finally:
        try:
            conn.close()
        except Exception:
            pass
# ---------------------------------------------------------------------------
# AUTH + APAccount handler
# ---------------------------------------------------------------------------

def handle_auth(conn, addr):
    t0 = time.time()

    try:
        # ---------------------------------------------------------------
        # 1. Initial RSA/DH handshake request
        # ---------------------------------------------------------------

        request = recv_exact(
            conn,
            214,
            timeout=10.0
        )

        log(
            "AUTH",
            f"Connected from {addr} "
            f"({len(request)}B)"
        )

        if len(request) != 214:
            log(
                "AUTH",
                "did not receive full "
                "214-byte handshake"
            )
            return

        print(
            f"[AUTH] header="
            f"{request[:16].hex()}",
            flush=True
        )

        # ---------------------------------------------------------------
        # 2. Build/send server AUTH ACK
        # ---------------------------------------------------------------

        response, aes_key = (
            build_auth_response(request)
        )

        conn.sendall(response)

        log(
            "AUTH",
            f"AUTH ACK sent "
            f"({len(response)}B)"
        )

        # ---------------------------------------------------------------
        # 3. Receive encrypted AP_CMD_VERIFY / cmd 3
        # ---------------------------------------------------------------

        ciphertext = recv_ap_frame(
            conn,
            timeout=15.0
        )

        if ciphertext is None:
            log(
                "AUTH",
                "client sent no AP request"
            )
            return

        if DEBUG_AUTH_HEX:
            log(
                "AUTH-DEBUG",
                f"AP RX encrypted {len(ciphertext)}B: {ciphertext.hex()}",
                level="DEBUG",
            )

        plaintext = ap_decrypt(
            aes_key,
            ciphertext
        )

        if DEBUG_AUTH_HEX:
            log(
                "AUTH-DEBUG",
                f"AP RX plaintext {len(plaintext)}B: {plaintext.hex()}",
                level="DEBUG",
            )

        hdr = parse_tdr_header(
            plaintext
        )

        log(
            "AUTH",
            "AP RX "
            f"msgsize={hdr['msgsize']} "
            f"version={hdr['version']} "
            f"seq={hdr['seqno']} "
            f"cmd={hdr['cmd']} "
            f"body={len(hdr['body'])}B"
        )

        if hdr["version"] != 1:
            log(
                "AUTH",
                "WARNING: unexpected "
                f"TDR version {hdr['version']}"
            )

        if hdr["msgsize"] != len(
            hdr["body"]
        ):
            log(
                "AUTH",
                "WARNING: TDR msgsize "
                f"says {hdr['msgsize']} "
                f"but body is "
                f"{len(hdr['body'])}B"
            )

        if hdr["cmd"] != 3:
            log(
                "AUTH",
                "LOGIN REJECTED: expected AP cmd=3, "
                f"got cmd={hdr['cmd']}"
            )
            result_plain = build_ap_result_plaintext(
                hdr["seqno"],
                uid=0,
                ticket=b"",
                error_code=1,
                error_message=b"Invalid AP request.\x00",
            )
            conn.sendall(build_ap_frame(aes_key, result_plain))
            return

        # ---------------------------------------------------------------
        # 4. Send AP_CMD_RESULT / cmd 4 success
        # ---------------------------------------------------------------

        try:
            _auth_server_port = conn.getsockname()[1]
            _auth_pid, _auth_process_name = identify_peer_process(
                addr, _auth_server_port
            )
        except Exception as _auth_peer_e:
            _auth_pid, _auth_process_name = None, None
            log("AUTH", f"r12 peer identity lookup failed: {_auth_peer_e}")

        auth_login_name = ""
        auth_account = None
        try:
            auth_login_name, auth_account = authenticate_ap_verify_body(
                hdr.get("body"),
                db_path=PLAYER_DB.db_path,
            )
        except Exception as _auth_error:
            log(
                "AUTH",
                "AP credential parse/verify error: "
                f"{type(_auth_error).__name__}: {_auth_error}",
            )

        if auth_account is None:
            log(
                "AUTH",
                f"LOGIN REJECTED login={auth_login_name!r} "
                f"OWNER={_auth_process_name or '<unresolved>'} "
                f"PID={_auth_pid}",
            )
            result_plain = build_ap_result_plaintext(
                hdr["seqno"],
                uid=0,
                ticket=b"",
                error_code=1,
                error_message=b"Invalid account, password, or account state.\x00",
            )
            conn.sendall(build_ap_frame(aes_key, result_plain))
            return

        auth_uid = int(auth_account["uin"])
        resolved_uid = _r12_uid_for_login(_auth_pid, auth_login_name)
        if resolved_uid != auth_uid:
            log(
                "AUTH",
                f"LOGIN REJECTED login={auth_login_name!r}: account UIN "
                f"{auth_uid} does not match stored game identity {resolved_uid}",
            )
            result_plain = build_ap_result_plaintext(
                hdr["seqno"],
                uid=0,
                ticket=b"",
                error_code=1,
                error_message=b"Account identity is inconsistent.\x00",
            )
            conn.sendall(build_ap_frame(aes_key, result_plain))
            return

        _r12_remember_login_for_uid(auth_uid, auth_login_name)
        log(
            "AUTH",
            "SQLite stable identity: "
            f"login={auth_login_name!r} "
            f"OWNER={_auth_process_name or '<unresolved>'} "
            f"PID={_auth_pid} -> uin={auth_uid}"
        )

        try:
            auth_ticket = issue_ticket(
                auth_uid,
                addr[0],
                aes_key,
                mode=3,
                db_path=PLAYER_DB.db_path,
                private_key_path=PRIVATE_KEY_PATH,
            )
        except Exception as _ticket_error:
            log(
                "AUTH",
                f"LOGIN REJECTED login={auth_login_name!r}: "
                f"could not create TGame ticket ({type(_ticket_error).__name__})",
            )
            result_plain = build_ap_result_plaintext(
                hdr["seqno"],
                uid=0,
                ticket=b"",
                error_code=1,
                error_message=b"Server login initialization failed.\x00",
            )
            conn.sendall(build_ap_frame(aes_key, result_plain))
            return

        result_plain = build_ap_result_plaintext(
            hdr["seqno"],
            uid=auth_uid,
            ticket=auth_ticket,
        )

        result_frame = build_ap_frame(
            aes_key,
            result_plain
        )

        if DEBUG_AUTH_HEX:
            log(
                "AUTH-DEBUG",
                f"AP TX cmd=4 plaintext {len(result_plain)}B (redacted)",
                level="DEBUG",
            )
            log(
                "AUTH-DEBUG",
                f"AP TX cmd=4 frame {len(result_frame)}B: {result_frame.hex()}",
                level="DEBUG",
            )
        else:
            log("AUTH", f"AP TX cmd=4 frame {len(result_frame)}B")

        conn.sendall(
            result_frame
        )

        # ---------------------------------------------------------------
        # 5. Client should now send cmd 5 acknowledgement
        # ---------------------------------------------------------------

        try:
            ack_ciphertext = recv_ap_frame(
                conn,
                timeout=10.0
            )
        except socket.timeout:
            ack_ciphertext = None

        if ack_ciphertext:
            if DEBUG_AUTH_HEX:
                log(
                    "AUTH-DEBUG",
                    f"AP RX second encrypted {len(ack_ciphertext)}B: {ack_ciphertext.hex()}",
                    level="DEBUG",
                )

            ack_plaintext = ap_decrypt(
                aes_key,
                ack_ciphertext
            )

            if DEBUG_AUTH_HEX:
                log(
                    "AUTH-DEBUG",
                    f"AP RX second plaintext {len(ack_plaintext)}B: {ack_plaintext.hex()}",
                    level="DEBUG",
                )

            if len(ack_plaintext) >= 10:
                ack_hdr = parse_tdr_header(
                    ack_plaintext
                )

                log(
                    "AUTH",
                    "AP RX second "
                    f"msgsize="
                    f"{ack_hdr['msgsize']} "
                    f"version="
                    f"{ack_hdr['version']} "
                    f"seq="
                    f"{ack_hdr['seqno']} "
                    f"cmd="
                    f"{ack_hdr['cmd']}"
                )

                if ack_hdr["cmd"] == 5:
                    log(
                        "AUTH",
                        "SUCCESS: client "
                        "accepted AP cmd=4 "
                        "and sent cmd=5"
                    )

        else:
            log(
                "AUTH",
                "No cmd=5 received"
            )

        # Let the client close naturally.
        try:
            conn.settimeout(3.0)

            extra = conn.recv(4096)

            if extra:
                log(
                    "AUTH",
                    f"EXTRA RX "
                    f"({len(extra)}B): "
                    f"{extra.hex()}"
                )

        except socket.timeout:
            pass

        log(
            "AUTH",
            f"finished after "
            f"{time.time() - t0:.2f}s"
        )

    except ConnectionResetError:
        log(
            "AUTH",
            "connection reset by client"
        )

    except Exception as e:
        log(
            "AUTH",
            f"ERROR: {type(e).__name__}: {e}"
        )

    finally:
        try:
            conn.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Placeholder DIR / ROLE handlers
#
# Once APAccount succeeds, whichever one the client contacts next
# is what we'll reverse next.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# ROLE / 65005 TPDU decoder helpers
#
# This is intentionally a decoder/probe first.  It does not fake a server reply
# until the next expected reply is proven from the client parser.
# ---------------------------------------------------------------------------

ROLE_BOOTSTRAP_TEA_KEY = b"aaaaaaaaaaaaaaaa"
ROLE_TEA_DELTA = 0x9E3779B9
ROLE_U32_MASK = 0xFFFFFFFF


def _role_tea_dec_block(block, key):
    import struct
    y, z = struct.unpack(">2I", block)
    a, b, c, d = struct.unpack(">4I", key)
    s = (ROLE_TEA_DELTA << 4) & ROLE_U32_MASK
    for _ in range(16):
        z = (z - ((((y << 4) & ROLE_U32_MASK) + c) ^ ((y + s) & ROLE_U32_MASK) ^ ((y >> 5) + d))) & ROLE_U32_MASK
        y = (y - ((((z << 4) & ROLE_U32_MASK) + a) ^ ((z + s) & ROLE_U32_MASK) ^ ((z >> 5) + b))) & ROLE_U32_MASK
        s = (s - ROLE_TEA_DELTA) & ROLE_U32_MASK
    return struct.pack(">2I", y, z)


def role_qqtea_decrypt(ciphertext, key=ROLE_BOOTSTRAP_TEA_KEY):
    if len(ciphertext) % 8 or len(ciphertext) < 16:
        return None, "bad ciphertext length"

    cur = _role_tea_dec_block(ciphertext[:8], key)
    padding = cur[0] & 7
    out_len = len(ciphertext) - padding - 10
    if out_len < 0:
        return None, "bad decoded length"

    index = padding + 1
    crypt_off = 8
    pre_crypt = b"\x00" * 8

    def next_block(cur_block, off):
        if off >= len(ciphertext):
            return None, None, None
        prev_cipher = ciphertext[off - 8:off]
        mixed = bytes(a ^ b for a, b in zip(ciphertext[off:off + 8], cur_block))
        return _role_tea_dec_block(mixed, key), off + 8, prev_cipher

    # Skip the two random bytes after the padding area.
    for _ in range(2):
        if index == 8:
            cur, crypt_off, pre_crypt = next_block(cur, crypt_off)
            if cur is None:
                return None, "ran out while skipping random bytes"
            index = 0
        index += 1

    plain = bytearray()
    for _ in range(out_len):
        if index == 8:
            cur, crypt_off, pre_crypt = next_block(cur, crypt_off)
            if cur is None:
                return None, "ran out while decrypting body"
            index = 0
        plain.append(cur[index] ^ pre_crypt[index])
        index += 1

    for n in range(7):
        if index == 8:
            cur, crypt_off, pre_crypt = next_block(cur, crypt_off)
            if cur is None:
                return bytes(plain), f"ran out while checking trailer byte {n}"
            index = 0
        trailer = cur[index] ^ pre_crypt[index]
        if trailer != 0:
            return bytes(plain), f"zero trailer failed at byte {n}: {trailer:02x}"
        index += 1

    return bytes(plain), "ok"


def decode_role_packet_for_log(data):
    import struct
    lines = []
    lines.append(f"ROLE decode: total={len(data)} bytes")
    if len(data) < 34:
        lines.append("too short for known 65005 AUTH frame")
        return lines

    lines.append(
        "header: "
        f"b0={data[0]:02x} version={data[1]:02x} cmd={data[2]:02x} "
        f"head_len={data[3]} enc_head_len={data[4]} "
        f"body_len={struct.unpack('>I', data[5:9])[0]}"
    )
    lines.append(
        "auth-head: "
        f"enc_method={struct.unpack('>I', data[9:13])[0]} "
        f"service_id={struct.unpack('>I', data[13:17])[0]} "
        f"auth_type={struct.unpack('>I', data[17:21])[0]} "
        f"uin={struct.unpack('>I', data[21:25])[0]} "
        f"auth_data_len={data[25]}"
    )

    auth_len = data[25]
    auth_data = data[26:26 + auth_len]
    if len(auth_data) >= 8:
        version = struct.unpack('>H', auth_data[0:2])[0]
        ts = struct.unpack('>I', auth_data[2:6])[0]
        enc_len = struct.unpack('>H', auth_data[6:8])[0]
        enc = auth_data[8:8 + enc_len]
        lines.append(f"unified-wrapper: version={version} time={ts} enc_len={enc_len}")
        plain, status = role_qqtea_decrypt(enc)
        lines.append(f"unified-decrypt: {status}")
        if plain is not None:
            lines.append(f"unified-plain-len={len(plain)} (contents redacted)")
            if len(plain) >= 50:
                uin = struct.unpack('>I', plain[6:10])[0]
                ts2 = struct.unpack('>I', plain[10:14])[0]
                session_key = plain[30:46]
                lines.append(
                    f"parsed-unified: uin={uin} time={ts2} "
                    f"session_key_len={len(session_key)} (value redacted)"
                )

    tail = data[26 + auth_len:]
    if data[0:3] == b"\x55\x0e\x03":
        lines.append(
            f"tail/body: offset={26 + auth_len} len={len(tail)} (contents redacted)"
        )
    else:
        lines.append(f"tail/body: offset={26 + auth_len} len={len(tail)} hex={tail.hex()}")
    return lines




ROLE_MODE3_IV = bytes(range(16))
ROLE_SYN_RAND = b"LOCAL_SYN_RAND01"  # exactly 16 bytes


def role_mode3_encrypt(plain, key):
    """Reimplementation of tacc_2_1.dll mode-3 (0x100E1460).

    AES-CBC with IV 00..0F and Tencent/TSF4G tail padding:
      random filler || b"tsf4g" || one-byte total pad length.
    Filler bytes are not validated by the client, so zeroes are deterministic.
    """
    if len(key) != 16:
        raise ValueError("mode3 requires a 16-byte key")
    rem = len(plain) & 0x0F
    pad_len = (16 - rem) if rem <= 10 else (32 - rem)
    filler_len = pad_len - 6
    padded = plain + (b"\x00" * filler_len) + b"tsf4g" + bytes([pad_len])
    enc = Cipher(algorithms.AES(key), modes.CBC(ROLE_MODE3_IV)).encryptor()
    return enc.update(padded) + enc.finalize()


def role_mode3_decrypt(ciphertext, key):
    """Reimplementation of tacc_2_1.dll 0x100E1620."""
    if len(key) != 16 or not ciphertext or (len(ciphertext) & 0x0F):
        return None, "bad mode3 input"
    dec = Cipher(algorithms.AES(key), modes.CBC(ROLE_MODE3_IV)).decryptor()
    raw = dec.update(ciphertext) + dec.finalize()
    if len(raw) < 6 or raw[-6:-1] != b"tsf4g":
        return None, f"bad tsf4g trailer raw={raw.hex()}"
    pad_len = raw[-1]
    if pad_len <= 0 or pad_len > len(raw):
        return None, f"bad pad length {pad_len}"
    plain_len = len(raw) - pad_len
    rem = plain_len & 0x0F
    expected = (16 - rem) if rem <= 10 else (32 - rem)
    if expected != pad_len:
        return None, f"pad mismatch got={pad_len} expected={expected}"
    return raw[:plain_len], "ok"


def role_extract_auth_state(data):
    """Extract live mode, UIN, session key and request sequence from cmd03."""
    st = {}
    if len(data) < 34 or data[2] != 0x03:
        return st
    try:
        st["mode"] = struct.unpack(">I", data[9:13])[0]
        st["uin"] = struct.unpack(">I", data[21:25])[0]
        auth_len = data[25]
        auth_data = data[26:26 + auth_len]
        if len(auth_data) >= 8:
            enc_len = struct.unpack(">H", auth_data[6:8])[0]
            enc = auth_data[8:8 + enc_len]
            plain, status = role_qqtea_decrypt(enc)
            if plain is not None and len(plain) >= 46:
                st["session_key"] = plain[30:46]
        head_len = data[3]
        body_len = struct.unpack(">I", data[5:9])[0]
        body = data[head_len:head_len + body_len]
        if st.get("mode") == 3 and st.get("session_key") and body:
            bp, bs = role_mode3_decrypt(body, st["session_key"])
            st["body_status"] = bs
            st["body_plain"] = bp
            if bp is not None and len(bp) >= 4:
                st["seq"] = struct.unpack(">I", bp[:4])[0]
                st["app_plain"] = bp[4:]
    except Exception as e:
        st["error"] = f"{type(e).__name__}: {e}"
    return st


def role_build_syn(session_key, seq, randstr=ROLE_SYN_RAND):
    """Build the server -> client TPDU SYN wire packet (cmd 08).

    Important correction vs v1:
      The client calls its generic receive routine for this first server reply
      with body_output=NULL. Therefore body_len MUST be 0 here. If we include
      an encrypted sequence/body, the generic receiver fails before the cmd08
      SYN parser gets a chance to run.

    TPDUSynInfo is the fixed 16-byte randstr. The SYN extension stores
    one-byte encrypted length followed by the mode-3 ciphertext at offset 0x0A.
    """
    if len(randstr) != 16:
        raise ValueError("randstr must be 16 bytes")
    syn_cipher = role_mode3_encrypt(randstr, session_key)
    head_len = 10 + len(syn_cipher)
    if head_len > 255 or len(syn_cipher) > 255:
        raise ValueError("SYN header too large")
    head = bytearray()
    head += bytes([0x00, 0x0C, 0x08, head_len, 0x04])
    head += struct.pack(">I", 0)          # body_len = 0 for first server SYN
    head += bytes([len(syn_cipher)])
    head += syn_cipher
    return bytes(head)




def role_build_tacc_one_private_entry_app(
    uin=10001,
    server_id=0x01010101,
    host="127.0.0.1",
    port=65005,
    cmdid=2,
    update_time=0,
):
    """v24: compact TDR success response with the corrected schema.

    Critical differences from v24:
      - keep the already-fixed cmd05 outer framing (NO extra 4-byte seq prefix)
      - serialize variable arrays compactly on the wire instead of sending
        fixed host-output padding
      - PrivateInfoCount = 1 on the wire
      - PrivateInfo.ServerID = DIR LeafID 0x01010101
      - PrivateData is the tacc_datadef.tdr six-byte record:
            LastActiveTime:u32 || rolecount:i16
        It is NOT IPv4:port.
      - PublicDataLen = 0 for this probe; GetBitMapInfo's return is ignored
        by OnDataArrive, so do not invent bitmap policy bytes here.
    """
    if update_time == 0:
        update_time = int(time.time())

    # tacc_datadef.tdr:
    #   PrivateData = BE u32 LastActiveTime || BE i16 rolecount
    private_data = struct.pack(">Ih", 0, 1)

    body = bytearray()
    body += struct.pack(">H", 0)                         # TaccRsp.Errno = success

    # RspInfoSucc compact wire order.
    body += struct.pack(">I", uin & 0xffffffff)          # Uin
    body += b"\x00"                                      # HasMorePkg
    body += struct.pack(">I", update_time & 0xffffffff)  # PublicInfo.UpdateTime
    body += struct.pack(">H", 0)                         # PublicDataLen = 0
    # no PublicData bytes
    body += struct.pack(">H", 1)                         # PrivateInfoCount = 1

    # PrivateInfo[0]
    body += struct.pack(">I", update_time & 0xffffffff)  # UpdateTime
    body += struct.pack(">I", server_id & 0xffffffff)    # ServerID = DIR leaf ID
    body += struct.pack(">H", len(private_data))         # PrivateDataLen = 6
    body += private_data                                 # 00 00 00 00 00 01

    total_len = 14 + len(body)
    pkg = bytearray()
    pkg += struct.pack(">I", total_len)
    pkg += struct.pack(">H", 0x00c8)
    pkg += struct.pack(">H", 0x0002)                     # request uses version 2
    pkg += struct.pack(">H", cmdid & 0xffff)             # response CmdID = 2
    pkg += struct.pack(">I", 0)                          # app Seq
    pkg += body

    return bytes(pkg), bytes(private_data)

def role_build_plain_tpdu_body_response(session_key, seq, app_payload):
    """Build server->client cmd05 carrying a TACC response.

    Critical fix vs v11-v14:
      In sub_100D6FD0 -> sub_100D60E0, when received command == 0x05 and
      the last decrypt/copy flag is 0, the client DOES NOT decrypt the body.
      It passes the body bytes directly to tdr_ntoh(pkg body).

    Therefore cmd05 body must be plaintext and begin directly with TACCCliPkg.

    The previous v18 prepended a uint32 TPDU sequence here. Static analysis of
    tacc_2_1.dll+CFA00 proves that was wrong: the root TACCCliPkg descriptor
    reads its 16-bit Version at input offset +6. With a 4-byte seq prefix it
    read the low 16 bits of PkgLen (0x0010) as Version and rejected 16 > 2.

    Do NOT AES-encrypt this body for cmd05 and do NOT prepend seq.
    """
    body_plain = bytes(app_payload)

    pkt = bytearray()
    pkt += bytes([0x00, 0x0c, 0x05, 0x09, 0x04])
    pkt += struct.pack('>I', len(body_plain))
    pkt += body_plain

    # Keep third return value for caller compatibility.
    return bytes(pkt), body_plain, body_plain



ROLE_SYN_VARIANT_STATE_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "role_syn_variant_state_unused_v4.txt",
)

ROLE_SYN_VARIANTS = [
    {"name": "00_raw16_aes_body0",       "b0": 0x00, "enc_head_len": 0x04, "plain": "raw16",     "crypto": "aes",  "body": "none"},
    {"name": "55_raw16_aes_body0",       "b0": 0x55, "enc_head_len": 0x04, "plain": "raw16",     "crypto": "aes",  "body": "none"},
    {"name": "00_len8_raw16_aes_body0",  "b0": 0x00, "enc_head_len": 0x04, "plain": "len8raw",   "crypto": "aes",  "body": "none"},
    {"name": "55_len8_raw16_aes_body0",  "b0": 0x55, "enc_head_len": 0x04, "plain": "len8raw",   "crypto": "aes",  "body": "none"},
    {"name": "00_len16_raw16_aes_body0", "b0": 0x00, "enc_head_len": 0x04, "plain": "len16raw",  "crypto": "aes",  "body": "none"},
    {"name": "00_len32_raw16_aes_body0", "b0": 0x00, "enc_head_len": 0x04, "plain": "len32raw",  "crypto": "aes",  "body": "none"},
    {"name": "00_raw16_nul_aes_body0",   "b0": 0x00, "enc_head_len": 0x04, "plain": "raw16nul",  "crypto": "aes",  "body": "none"},
    {"name": "00_nul_raw16_aes_body0",   "b0": 0x00, "enc_head_len": 0x04, "plain": "nulraw16",  "crypto": "aes",  "body": "none"},
    {"name": "00_raw16_aes_bodyseq",     "b0": 0x00, "enc_head_len": 0x04, "plain": "raw16",     "crypto": "aes",  "body": "seq"},
    {"name": "55_raw16_aes_bodyseq",     "b0": 0x55, "enc_head_len": 0x04, "plain": "raw16",     "crypto": "aes",  "body": "seq"},
    {"name": "00_raw16_plain_body0",     "b0": 0x00, "enc_head_len": 0x04, "plain": "raw16",     "crypto": "none", "body": "none"},
    {"name": "00_len8_raw16_plain_body0","b0": 0x00, "enc_head_len": 0x04, "plain": "len8raw",   "crypto": "none", "body": "none"},
    {"name": "00_raw16_aes_ehlen0",      "b0": 0x00, "enc_head_len": 0x00, "plain": "raw16",     "crypto": "aes",  "body": "none"},
    {"name": "55_len8_raw16_aes_bodyseq","b0": 0x55, "enc_head_len": 0x04, "plain": "len8raw",   "crypto": "aes",  "body": "seq"},
]


def role_syn_plaintext(kind, randstr):
    if kind == "raw16":
        return randstr
    if kind == "len8raw":
        return bytes([len(randstr)]) + randstr
    if kind == "len16raw":
        return struct.pack(">H", len(randstr)) + randstr
    if kind == "len32raw":
        return struct.pack(">I", len(randstr)) + randstr
    if kind == "raw16nul":
        return randstr + b"\x00"
    if kind == "nulraw16":
        return b"\x00" + randstr
    raise ValueError(f"unknown SYN plaintext variant: {kind}")


def role_build_syn_variant(session_key, seq, variant, randstr=ROLE_SYN_RAND):
    plain = role_syn_plaintext(variant["plain"], randstr)

    if variant["crypto"] == "aes":
        syn_field = role_mode3_encrypt(plain, session_key)
    elif variant["crypto"] == "none":
        syn_field = plain
    else:
        raise ValueError(f"unknown SYN crypto variant: {variant['crypto']}")

    body = b""
    if variant["body"] == "seq":
        body = role_mode3_encrypt(struct.pack(">I", seq & 0xffffffff), session_key)
    elif variant["body"] != "none":
        raise ValueError(f"unknown SYN body variant: {variant['body']}")

    head_len = 10 + len(syn_field)
    if head_len > 255 or len(syn_field) > 255:
        raise ValueError("SYN variant header too large")

    pkt = bytearray()
    pkt += bytes([variant["b0"], 0x0C, 0x08, head_len, variant["enc_head_len"]])
    pkt += struct.pack(">I", len(body))
    pkt += bytes([len(syn_field)])
    pkt += syn_field
    pkt += body
    return bytes(pkt), plain, syn_field, body


def role_choose_syn_variant():
    # v4: static trace says the generic TQQAPI path uses the real TPDU magic byte 0x55.
    # The captured client.exe request used 0x00 because CPlayerInfoQuerier manually builds
    # its first AUTH frame and leaves byte 0 zeroed before the transport wraps it.
    # Server -> client SYN should follow the normal TQQAPI packet shape.
    variant = {
        "name": "v4_exact_static_55_raw16_aes_body0",
        "b0": 0x55,
        "enc_head_len": 0x04,
        "plain": "raw16",
        "crypto": "aes",
        "body": "none",
    }
    return 0, variant, "forced v4 from static cmd08 parser: b0=0x55, raw TPDUSynInfo[16], encrypted header, no body"

def role_decode_synack(data, session_key):
    if len(data) < 10:
        return [f"SYNACK too short: {len(data)}"]
    lines=[]
    try:
        cmd=data[2]
        head_len=data[3]
        body_len=struct.unpack(">I", data[5:9])[0]
        lines.append(f"follow-up header: version={data[1]:02x} cmd={cmd:02x} head_len={head_len} enc_head_len={data[4]} body_len={body_len}")
        if cmd == 0x09:
            enc_len=data[9]
            enc=data[10:10+enc_len]
            p, status=role_mode3_decrypt(enc, session_key)
            lines.append(f"SYNACK rand decrypt: {status}")
            if p is not None:
                lines.append(f"SYNACK rand plain={p!r} hex={p.hex()} matches={p == ROLE_SYN_RAND}")
        if body_len and head_len + body_len <= len(data):
            bp, bs=role_mode3_decrypt(data[head_len:head_len+body_len], session_key)
            lines.append(f"follow-up body decrypt: {bs} plain={bp.hex() if bp is not None else None}")
    except Exception as e:
        lines.append(f"SYNACK decode error: {type(e).__name__}: {e}")
    return lines


def identify_peer_process(addr, server_port):
    """
    On Windows, map the accepted connection's ephemeral source port back
    to its owning PID/process name using netstat -ano + tasklist.
    """
    if os.name != "nt":
        return None, None

    remote_port = int(addr[1])

    try:
        cp = subprocess.run(
            ["netstat", "-ano", "-p", "tcp"],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=3.0,
        )

        pid = None

        for raw in cp.stdout.splitlines():
            parts = raw.split()

            if len(parts) < 5 or parts[0].upper() != "TCP":
                continue

            local_ep = parts[1]
            remote_ep = parts[2]
            state = parts[3].upper()
            pid_text = parts[4]

            # We want the CLIENT side of this loopback connection:
            #
            #   local   127.0.0.1:<ephemeral>
            #   remote  127.0.0.1:<server_port>
            #
            try:
                local_port = int(local_ep.rsplit(":", 1)[1])
                peer_port = int(remote_ep.rsplit(":", 1)[1])
            except Exception:
                continue

            if (
                local_port == remote_port
                and peer_port == int(server_port)
                and state in ("ESTABLISHED", "SYN_SENT", "SYN_RECEIVED")
            ):
                try:
                    pid = int(pid_text)
                except ValueError:
                    pid = None
                break

        if pid is None:
            return None, None

        cp2 = subprocess.run(
            [
                "tasklist",
                "/FI", f"PID eq {pid}",
                "/FO", "CSV",
                "/NH",
            ],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=3.0,
        )

        process_name = None

        rows = list(csv.reader(io.StringIO(cp2.stdout)))

        if rows and rows[0]:
            first = rows[0][0].strip()

            if first and not first.upper().startswith("INFO:"):
                process_name = first

        return pid, process_name

    except Exception as e:
        log("PID", f"peer-process lookup failed: {type(e).__name__}: {e}")
        return None, None



# ---------------------------------------------------------------------------
# TGame / ProtocalHandler mode-4 handshake helpers (v26)
# ---------------------------------------------------------------------------

TGAME_SYN_RAND = b"LOCAL_SYN_RAND01"  # exactly 16 bytes




TGAME_KEY_ALPHABET = set(b"ABCDEFGHIJKMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789")
TGAME_MODE3_IV = bytes(range(16))

def _tgame_enable_debug_privilege():
    """Enable SeDebugPrivilege in this server process when available."""
    if os.name != "nt":
        return False, "not-windows"
    import ctypes
    from ctypes import wintypes

    TOKEN_ADJUST_PRIVILEGES = 0x20
    TOKEN_QUERY = 0x08
    SE_PRIVILEGE_ENABLED = 0x02

    class LUID(ctypes.Structure):
        _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

    class LUID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]

    class TOKEN_PRIVILEGES(ctypes.Structure):
        _fields_ = [("PrivilegeCount", wintypes.DWORD),
                    ("Privileges", LUID_AND_ATTRIBUTES * 1)]

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    token = wintypes.HANDLE()
    if not adv.OpenProcessToken(k32.GetCurrentProcess(),
                                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                                ctypes.byref(token)):
        return False, f"OpenProcessToken err={ctypes.get_last_error()}"
    try:
        luid = LUID()
        if not adv.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid)):
            return False, f"LookupPrivilegeValueW err={ctypes.get_last_error()}"
        tp = TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = luid
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
        ctypes.set_last_error(0)
        if not adv.AdjustTokenPrivileges(token, False, ctypes.byref(tp), 0, None, None):
            return False, f"AdjustTokenPrivileges err={ctypes.get_last_error()}"
        err = ctypes.get_last_error()
        if err == 1300:  # ERROR_NOT_ALL_ASSIGNED
            return False, "SeDebugPrivilege not assigned (run server elevated)"
        return True, "SeDebugPrivilege enabled"
    finally:
        k32.CloseHandle(token)



# ---------------------------------------------------------------------------
# TGame AuthAP ticket-anchored crypto-state recovery (v42)
# ---------------------------------------------------------------------------

# ProtocalHandler live AuthAP object layout, expressed relative to the first
# byte of the ticket at outer+0x3A0.  The key and ticket are copied into the
# same object by the live setter at ProtocalHandler+0x33C30.
_TGA_OFF_KEY       = -0x1B8   # outer+0x1E8, 16 bytes
_TGA_OFF_MODE      = -0x1D0   # outer+0x1D0, u32
_TGA_OFF_SVCID     = -0x1C8   # outer+0x1D8, u32
_TGA_OFF_UIN       = -0x1BC   # outer+0x1E4, u32
_TGA_OFF_TICKETLEN = -0x004   # outer+0x39C, u32
_TGA_OFF_AUTHTYPE  = +0x404   # outer+0x7A4, must be 4 for AuthAP
_TGA_OFF_HANDLER   = -0x1EC   # outer+0x1B4, CTdrProtocalHandler*
_TGA_HANDLER_CONN  = 0x88
_TGA_CONN_RAWKEY   = 0x50
_TGA_CONN_MODE     = 0x84

# A TGame process can keep the GEO AuthAP object alive while creating a second
# AuthAP object for the ZONE socket.  Both contain the same ticket.  Track the
# exact object anchor already consumed by each successful connection so the
# second handshake cannot accidentally reuse the GEO connection's key.
_TGAME_USED_AUTH_ANCHORS = {}
_TGAME_USED_AUTH_ANCHORS_LOCK = threading.Lock()


def tgame_recover_key_by_ticket(pid, ticket, want_authtype=4, exclude_anchors=None):
    """Recover the exact live TGame mode/key by anchoring on its AuthAP ticket.

    This is an exact-match, read-only lookup in the local TGame process:
      ticket bytes -> containing AuthAP object -> key/mode.

    Unlike the abandoned heuristic key scanners, candidates are accepted only
    when the surrounding object fields validate (ticket length/AuthType) and
    are independently cross-checked through CTdrProtocalHandler->hQQClt.
    """
    if os.name != "nt" or pid is None:
        return None, None, "not-windows/no-pid"
    if isinstance(ticket, str):
        ticket = ticket.encode("latin1", "replace")
    ticket = bytes(ticket or b"")
    if len(ticket) < 8:
        return None, None, f"ticket too short to anchor on ({len(ticket)}B)"

    exclude_anchors = set(int(x) for x in (exclude_anchors or ()))

    import ctypes
    from ctypes import wintypes

    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010
    MEM_COMMIT = 0x1000
    MEM_PRIVATE = 0x20000
    PAGE_GUARD = 0x100
    PAGE_NOACCESS = 0x01

    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_void_p),
            ("AllocationBase", ctypes.c_void_p),
            ("AllocationProtect", wintypes.DWORD),
            ("RegionSize", ctypes.c_size_t),
            ("State", wintypes.DWORD),
            ("Protect", wintypes.DWORD),
            ("Type", wintypes.DWORD),
        ]

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k32.OpenProcess.restype = wintypes.HANDLE
    k32.VirtualQueryEx.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p,
        ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t
    ]
    k32.VirtualQueryEx.restype = ctypes.c_size_t
    k32.ReadProcessMemory.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
        ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)
    ]
    k32.ReadProcessMemory.restype = wintypes.BOOL
    k32.CloseHandle.argtypes = [wintypes.HANDLE]

    def read_mem(h, addr, n):
        if not addr or addr < 0 or n <= 0:
            return None
        buf = (ctypes.c_ubyte * n)()
        got = ctypes.c_size_t(0)
        if not k32.ReadProcessMemory(
            h, ctypes.c_void_p(int(addr)), buf, n, ctypes.byref(got)
        ):
            return None
        if got.value != n:
            return None
        return bytes(buf)

    def read_u32(h, addr):
        b = read_mem(h, addr, 4)
        return None if b is None else struct.unpack("<I", b)[0]

    access = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
    h = k32.OpenProcess(access, False, int(pid))
    if not h:
        # Reuse the existing local-backend privilege helper once, then retry.
        _tgame_enable_debug_privilege()
        h = k32.OpenProcess(access, False, int(pid))
    if not h:
        return None, None, (
            f"OpenProcess({pid}) failed err={ctypes.get_last_error()}"
        )

    try:
        candidates = []
        addr = 0
        mbi = MEMORY_BASIC_INFORMATION()

        # 32-bit TGame user address range. Search only committed private pages;
        # the ticket copy lives in the mutable AuthAP object, not image/mapped data.
        while addr < 0x7FFF0000:
            q = k32.VirtualQueryEx(
                h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)
            )
            if not q:
                break

            base = int(mbi.BaseAddress or addr)
            size = int(mbi.RegionSize or 0x1000)

            usable = (
                mbi.State == MEM_COMMIT
                and mbi.Type == MEM_PRIVATE
                and not (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))
                and size <= 0x04000000
            )

            if usable:
                blk = read_mem(h, base, size)
                if blk:
                    pos = blk.find(ticket)
                    while pos >= 0:
                        candidates.append(base + pos)
                        pos = blk.find(ticket, pos + 1)

            next_addr = base + max(size, 0x1000)
            if next_addr <= addr:
                break
            addr = next_addr

        if not candidates:
            return None, None, f"current AP ticket not found in TGame PID={pid}"

        rejected = []
        valid = []
        for anchor in candidates:
            ticket_len = read_u32(h, anchor + _TGA_OFF_TICKETLEN)
            auth_type = read_u32(h, anchor + _TGA_OFF_AUTHTYPE)

            if ticket_len != len(ticket) or auth_type != want_authtype:
                rejected.append(
                    f"{hex(anchor)}:len={ticket_len},auth={auth_type}"
                )
                continue

            key = read_mem(h, anchor + _TGA_OFF_KEY, 16)
            mode = read_u32(h, anchor + _TGA_OFF_MODE)
            if key is None or mode not in (2, 3, 4) or key == bytes(16):
                rejected.append(
                    f"{hex(anchor)}:mode={mode},key_present={key is not None and key != bytes(16)}"
                )
                continue

            info = {
                "source": "AuthAP ticket anchor",
                "pid": int(pid),
                "anchor": hex(anchor),
                "outer": hex(anchor - 0x3A0),
                "uin": read_u32(h, anchor + _TGA_OFF_UIN),
                "service_id": read_u32(h, anchor + _TGA_OFF_SVCID),
                "auth_type": auth_type,
                "mode": mode,
                "verified": False,
            }

            # Independent confirmation through the exact handler/connection
            # that SetEncryptMethod populates.
            handler = read_u32(h, anchor + _TGA_OFF_HANDLER)
            if handler:
                conn = read_u32(h, handler + _TGA_HANDLER_CONN)
                if conn:
                    conn_key = read_mem(h, conn + _TGA_CONN_RAWKEY, 16)
                    conn_mode = read_u32(h, conn + _TGA_CONN_MODE)
                    info["handler"] = hex(handler)
                    info["conn"] = hex(conn)
                    info["conn_mode"] = conn_mode
                    if conn_key == key and conn_mode == mode:
                        info["verified"] = True
                    else:
                        info["crosscheck_key_present"] = (
                            conn_key is not None and conn_key != bytes(16)
                        )
                        info["crosscheck_mode"] = conn_mode

            valid.append((bool(info.get("verified")), int(anchor), key, mode, info))

        if valid:
            # Prefer a never-before-used AuthAP object for this PID. Within that
            # set, prefer a candidate independently verified through hQQClt.
            fresh = [v for v in valid if v[1] not in exclude_anchors]
            if exclude_anchors and not fresh:
                return None, None, (
                    "validated ticket anchors exist, but all belong to prior "
                    f"connections: {[hex(v[1]) for v in valid]}"
                )
            pool = fresh if fresh else valid
            pool.sort(key=lambda v: (v[0], v[1]), reverse=True)
            _verified, _anchor, key, mode, info = pool[0]
            info["fresh_for_connection"] = _anchor not in exclude_anchors
            info["candidate_count"] = len(valid)
            return key, mode, info

        return None, None, (
            "ticket anchor candidates found but none validated: "
            + "; ".join(rejected[:8])
        )
    finally:
        k32.CloseHandle(h)


def tgame_find_internal_crypto_state(pid):
    """Locate ProtocalHandler's live connection key in the local TGame process.

    Static layout recovered from ProtocalHandler.dll:
      conn+0x50 : raw 16-byte generated key
      conn+0x84 : encryption mode (2/3/4)

    This is deliberately read-only and is used only for the local replacement
    backend, because a server-generated AP ticket does not carry the original
    Tencent-side credential material needed to derive the client-generated key.
    """
    if os.name != "nt" or pid is None:
        return None, None, "not-windows/no-pid"

    import ctypes
    from ctypes import wintypes

    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010
    MEM_COMMIT = 0x1000
    MEM_PRIVATE = 0x20000
    PAGE_GUARD = 0x100
    PAGE_NOACCESS = 0x01
    # ProtocalHandler connection objects are mutable process-private storage.
    # Exclude mapped/image pages: v35's three "AchievementSyste" hits were
    # static image strings that merely happened to satisfy the alphabet test.
    WRITABLE_PROTECT = {0x04, 0x08, 0x40, 0x80}  # RW/WC and executable variants

    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_void_p),
            ("AllocationBase", ctypes.c_void_p),
            ("AllocationProtect", wintypes.DWORD),
            ("RegionSize", ctypes.c_size_t),
            ("State", wintypes.DWORD),
            ("Protect", wintypes.DWORD),
            ("Type", wintypes.DWORD),
        ]

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k32.OpenProcess.restype = wintypes.HANDLE
    k32.VirtualQueryEx.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p,
        ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t
    ]
    k32.VirtualQueryEx.restype = ctypes.c_size_t
    k32.ReadProcessMemory.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
        ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)
    ]
    k32.ReadProcessMemory.restype = wintypes.BOOL
    k32.CloseHandle.argtypes = [wintypes.HANDLE]

    # v27 hit ERROR_ACCESS_DENIED (5) here. Enable SeDebugPrivilege first,
    # then try the smallest useful access mask before adding query rights.
    dbg_ok, dbg_status = _tgame_enable_debug_privilege()

    # VirtualQueryEx needs query rights as well as VM_READ.  v28 accepted
    # a VM_READ-only handle, then its first VirtualQueryEx returned zero, which
    # looked like "no key candidate".  Prefer QUERY+VM_READ in v29.
    attempts = [
        ("QUERY+VM_READ", PROCESS_QUERY_INFORMATION | PROCESS_VM_READ),
        ("QUERY_LIMITED+VM_READ", 0x1000 | PROCESS_VM_READ),
    ]
    h = None
    errs = []
    for label, access in attempts:
        ctypes.set_last_error(0)
        h_try = k32.OpenProcess(access, False, int(pid))
        if h_try:
            h = h_try
            open_label = label
            break
        errs.append(f"{label}=err{ctypes.get_last_error()}")
    if not h:
        return None, None, (
            f"OpenProcess denied after privilege setup ({dbg_status}); "
            + ", ".join(errs)
        )

    candidates = []
    try:
        addr = 0x10000
        mbi = MEMORY_BASIC_INFORMATION()
        max_addr = 0x7FFF0000
        regions_seen = 0
        readable_regions = 0
        while addr < max_addr:
            ctypes.set_last_error(0)
            n = k32.VirtualQueryEx(
                h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)
            )
            if not n:
                err = ctypes.get_last_error()
                if regions_seen == 0:
                    return None, None, (
                        f"VirtualQueryEx failed before first region err={err} "
                        f"open={open_label} privilege={dbg_status}"
                    )
                break
            regions_seen += 1
            base = int(mbi.BaseAddress or 0)
            size = int(mbi.RegionSize)
            base_protect = int(mbi.Protect) & 0xFF
            if (mbi.State == MEM_COMMIT and
                    int(mbi.Type) == MEM_PRIVATE and
                    base_protect in WRITABLE_PROTECT and
                    size and
                    not (mbi.Protect & PAGE_GUARD) and
                    not (mbi.Protect & PAGE_NOACCESS)):
                readable_regions += 1
                # Keep reads bounded; connection objects are small and a
                # generated key cannot straddle more than our overlap.
                off = 0
                overlap = b""
                while off < size:
                    want = min(8 * 1024 * 1024, size - off)
                    buf = ctypes.create_string_buffer(want)
                    got = ctypes.c_size_t()
                    ok = k32.ReadProcessMemory(
                        h, ctypes.c_void_p(base + off), buf, want, ctypes.byref(got)
                    )
                    if ok and got.value:
                        chunk = overlap + buf.raw[:got.value]
                        origin = base + off - len(overlap)
                        # v30 FAST PATH: do not test every byte in Python.
                        # Search only 16-byte runs from ProtocalHandler's exact
                        # generator alphabet, then validate conn+0x84 mode.
                        import re
                        alphabet = b"ABCDEFGHIJKMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"
                        aset = set(alphabet)
                        key_re = re.compile(
                            rb"[ABCDEFGHIJKMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789]{16}"
                        )
                        for m in key_re.finditer(chunk):
                            i = m.start()
                            if i + 0x38 > len(chunk):
                                continue

                            # The live key is a fixed 16-byte field at conn+0x50.
                            # v35 false positives were 16-byte windows inside
                            # longer printable identifiers ("AchievementSyste",
                            # "72a525cnpExitInt"). Reject any candidate that is
                            # immediately adjacent to another generator-alphabet
                            # byte; that makes it a substring, not a standalone
                            # 16-byte key field.
                            if i > 0 and chunk[i - 1] in aset:
                                continue
                            if i + 16 < len(chunk) and chunk[i + 16] in aset:
                                continue

                            mode = struct.unpack_from("<I", chunk, i + 0x34)[0]

                            # This TGame AUTH path advertises field0=3 on every
                            # captured cmd03.  Do not let unrelated mode-2/4
                            # coincidences enter the candidate pool.
                            if mode != 3:
                                continue

                            key = bytes(m.group(0))

                            # Generated keys should look random rather than like
                            # English/C++ identifiers.  Use diversity as a
                            # rejection filter, but do not require a digit
                            # (a legitimate random key can contain none).
                            distinct = len(set(key))
                            transitions = sum(
                                1 for a, b in zip(key, key[1:])
                                if (65 <= a <= 90) != (65 <= b <= 90)
                                or (48 <= a <= 57) != (48 <= b <= 57)
                            )
                            if distinct < 10 or transitions < 3:
                                continue

                            candidates.append((origin + i, key, mode))
                        overlap = chunk[-0x50:]
                    else:
                        overlap = b""
                    off += want
            nxt = base + max(size, 0x1000)
            if nxt <= addr:
                break
            addr = nxt
    finally:
        k32.CloseHandle(h)

    # Deduplicate exact address/key/mode tuples.
    uniq = []
    seen = set()
    for item in candidates:
        if item not in seen:
            seen.add(item)
            uniq.append(item)

    if not uniq:
        return None, None, (
            "no ProtocalHandler key-layout candidate found "
            f"(regions={regions_seen} readable={readable_regions} "
            f"open={open_label} privilege={dbg_status})"
        )

    # Only mutable MEM_PRIVATE candidates reach this point. field0 in the
    # observed cmd03 is 3; prefer mode 3 when present, but never guess between
    # multiple live-looking objects.
    mode3 = [x for x in uniq if x[2] == 3]
    pool = mode3 if mode3 else uniq
    if len(pool) != 1:
        detail = ", ".join(
            f"0x{a:08X}:{k.decode('ascii','replace')}:m{m}" for a,k,m in pool[:8]
        )
        return None, None, f"ambiguous crypto-state candidates ({len(pool)}): {detail}"

    a, key, mode = pool[0]
    return key, mode, (
        f"TGame memory key@0x{a:08X} conn@0x{a-0x50:08X} "
        f"open={open_label} privilege={dbg_status}"
    )


def _tgame_mode3_cbc_encrypt(framed, key):
    """ProtocalHandler +0x8B710 direction=1: AES-CBC with IV 00..0F.

    Static translation of the DLL helper: XOR each plaintext block with the
    previous ciphertext block (the fixed IV for block 0), then AES-encrypt.
    """
    if len(framed) & 0x0F:
        raise ValueError("mode3 framed plaintext must be block aligned")
    aes = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    prev = TGAME_MODE3_IV
    out = bytearray()
    for off in range(0, len(framed), 16):
        block = bytes(a ^ b for a, b in zip(framed[off:off+16], prev))
        c = aes.update(block)
        out += c
        prev = c
    aes.finalize()
    return bytes(out)


def _tgame_mode3_cbc_decrypt(ciphertext, key):
    """Inverse of ProtocalHandler +0x8B710 direction=0."""
    if len(ciphertext) & 0x0F:
        raise ValueError("mode3 ciphertext must be block aligned")
    aes = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    prev = TGAME_MODE3_IV
    out = bytearray()
    for off in range(0, len(ciphertext), 16):
        c = bytes(ciphertext[off:off+16])
        p0 = aes.update(c)
        out += bytes(a ^ b for a, b in zip(p0, prev))
        prev = c
    aes.finalize()
    return bytes(out)


def tgame_mode3_encrypt(plain, key):
    """Exact framing used by ProtocalHandler mode-3 encoder (+0x8B8E0)."""
    if len(key) != 16:
        raise ValueError("mode3 requires a 16-byte AES key")
    rem = len(plain) & 0x0F
    pad_len = (16 if rem <= 10 else 32) - rem
    random_len = pad_len - 6
    if random_len < 0:
        raise ValueError("invalid mode3 padding calculation")
    framed = bytes(plain) + os.urandom(random_len) + b"tsf4g" + bytes([pad_len])
    if len(framed) % 16:
        raise AssertionError("mode3 framed length is not block aligned")
    return _tgame_mode3_cbc_encrypt(framed, key)


def tgame_mode3_decrypt(ciphertext, key):
    """ProtocalHandler mode-3 decoder (+0x8BAA0), inverse of +0x8B8E0."""
    if len(key) != 16:
        raise ValueError("mode3 requires a 16-byte AES key")
    if not ciphertext or (len(ciphertext) & 0x0F):
        raise ValueError("mode3 ciphertext must be a non-empty multiple of 16")
    framed = _tgame_mode3_cbc_decrypt(bytes(ciphertext), key)
    if len(framed) < 16 or framed[-6:-1] != b"tsf4g":
        raise ValueError("mode3 trailer mismatch")
    pad_len = framed[-1]
    if pad_len <= 0 or pad_len > len(framed):
        raise ValueError("mode3 invalid padding length")
    payload_len = len(framed) - pad_len
    rem = payload_len & 0x0F
    expected = (16 if rem <= 10 else 32) - rem
    if pad_len != expected:
        raise ValueError(f"mode3 padding mismatch got={pad_len} expected={expected}")
    return framed[:payload_len]

def tgame_parse_wire_encrypted_body(pkt):
    """Parse the compact cmd08/cmd09 wire form used by this TGame build."""
    if len(pkt) < 13 or pkt[0:2] != b"\x55\x0e":
        raise ValueError("not a TGame compact TPDU")
    total = struct.unpack(">I", pkt[4:8])[0]
    enc_len = pkt[12]
    if 13 + enc_len > len(pkt):
        raise ValueError(
            f"truncated encrypted body len={enc_len} packet={len(pkt)}"
        )
    return pkt[2], total, pkt[13:13 + enc_len]


def tgame_parse_generic_body(pkt):
    """Parse the normal 12-byte TPDUBase + encrypted body form.

    After CHGSKEY, TGame switches from SYN/SYNACK head-extension traffic to
    ordinary cmd00 packets whose encrypted payload length is BodyLen at +8.
    """
    if len(pkt) < 12 or pkt[0:2] != b"\x55\x0e":
        raise ValueError("not a TGame TPDU")
    cmd = pkt[2]
    head_len = struct.unpack(">I", pkt[4:8])[0]
    body_len = struct.unpack(">I", pkt[8:12])[0]
    if head_len < 12 or head_len > len(pkt):
        raise ValueError(
            f"invalid TPDU head_len={head_len} packet={len(pkt)}"
        )
    if head_len + body_len > len(pkt):
        raise ValueError(
            f"truncated TPDU body len={body_len} head={head_len} packet={len(pkt)}"
        )
    return cmd, head_len, body_len, pkt[head_len:head_len + body_len]


def tgame_split_generic_stream(data):
    """Split a TCP byte stream into complete post-CHGSKEY TGame TPDU frames.

    TCP recv() is not message-framed: one recv may contain multiple TPDUs,
    or only part of one TPDU.  Generic post-CHGSKEY frames are self-sized by
    HeadLen (+4) + BodyLen (+8), both big-endian u32 values.
    """
    data = bytes(data)
    frames = []
    off = 0

    while len(data) - off >= 12:
        if data[off:off + 2] != b"\x55\x0e":
            raise ValueError(
                f"stream desync at +0x{off:x}: "
                f"{data[off:off + 16].hex()}"
            )

        head_len = struct.unpack(">I", data[off + 4:off + 8])[0]
        body_len = struct.unpack(">I", data[off + 8:off + 12])[0]

        if head_len < 12 or head_len > 0x10000:
            raise ValueError(
                f"invalid stream HeadLen={head_len} at +0x{off:x}"
            )

        frame_len = head_len + body_len
        if frame_len < 12 or frame_len > 0x400000:
            raise ValueError(
                f"invalid stream frame_len={frame_len} at +0x{off:x}"
            )

        if len(data) - off < frame_len:
            break

        frames.append(data[off:off + frame_len])
        off += frame_len

    return frames, data[off:]


# C2GEO application protocol, confirmed from proto_c2geo.tdr:
#   magic 0x8202
#   C2GEO_REQ_PINGLIST = 0x1001
#   GEO2C_RES_PINGLIST = 0x2001
# C2GEOPkgHead is four big-endian u16 fields:
#   Magic, Cmd, HeadLen, BodyLen
# GEO2C_ResPingList with ServerCount=0 serializes to:
#   Result(u16), ServerCount(u16), MaxDelayInMs(u32)
TGAME_GEO_MAGIC = 0x8202
TGAME_GEO_REQ_ZONELIST = 0x1000
TGAME_GEO_RES_ZONELIST = 0x2000
TGAME_GEO_REQ_PINGLIST = 0x1001
TGAME_GEO_RES_PINGLIST = 0x2001

# Recovered from proto_c2geo.tdr / proto_c2zn.tdr macro tables.
GEO_ERR_SUCC = 0x8B00
ZONE_ERR_SUCC = 0x8100
ZONE_LOGIN_NEWACCOUNT = 0x01A7

# Stock PH GfxMovie_CreateRole::OnCreateRoleReturn result mapping.
ZONE_FAIL_ILLEGAL_NICKNAME = 0x0101
ZONE_FAIL_SERVER_BUSY = 0x0102
ZONE_FAIL_NICKNAME_EXIST = 0x0103
ZONE_FAIL_NOACCOUNTEXIST = 0x0104

TGAME_ZN_MAGIC = 0x3243
TGAME_ZN_REQ_LOGIN = 0xA000
TGAME_ZN_RES_LOGIN = 0xA001
TGAME_ZN_REQ_CREATEACCOUNT = 0xA002
TGAME_ZN_RES_CREATEACCOUNT = 0xA003
TGAME_ZN_REQ_HEARTBEAT = 0xA004
# Prior-recovered stock first-login nickname validation family.
TGAME_ZN_REQ_CHECK_NICKNAME = 0xA144
TGAME_ZN_RES_CHECK_NICKNAME = 0xA145

# FIRST-NICKNAME-v22: stock post-CreateAccount role-selection completion.
# Recovered/previously verified in v120:
#   C2ZN_ReqChangeRole = 0xA146
#   ZN2C_ResChangeRole = 0xA147
TGAME_ZN_REQ_CHANGE_ROLE = 0xA146
TGAME_ZN_RES_CHANGE_ROLE = 0xA147

# FIRST-NICKNAME-v26:
#   Fix same-session CreateRole completion ordering by deferring first-account
#   A006 PlayerProps until after A147 ChangeLoginRole success.
#
# FIRST-NICKNAME-v24: stock post-role season-time startup gates.
# v23 proved the client receives F125/F127 but immediately retries F124/F126.
# UTGame callback metadata proves both completion delegates take ErrorCode, so
# the response must expose the normal zone Result before the season fields.
#   F124 C2ZN_ReqPLMatchSeasonTime -> F125 ZN2C_ResPLMatchSeasonTime
#   F126 C2ZN_ReqCLMatchSeasonTime -> F127 ZN2C_ResCLMatchSeasonTime
# Request: one padding byte. Response kept identical to verified v25.
TGAME_ZN_REQ_PLMATCH_SEASON_TIME = 0xF124
TGAME_ZN_RES_PLMATCH_SEASON_TIME = 0xF125
TGAME_ZN_REQ_CLMATCH_SEASON_TIME = 0xF126
TGAME_ZN_RES_CLMATCH_SEASON_TIME = 0xF127

# FIRST-NICKNAME-v6: stock startup activity gate observed live immediately
# after A001 NEWACCOUNT. Older PH captures verified C119 -> C11A and the
# C11A payload as one big-endian u32 CurrOnlineTime value.
TGAME_ZN_REQ_CURR_ONLINE_TIME = 0xC119
TGAME_ZN_RES_CURR_ONLINE_TIME = 0xC11A

TGAME_ZN_NTF_PLAYERINFO = 0xA005
TGAME_ZN_NTF_PLAYERPROPS = 0xA006

# v111: live backpack/loadout operation family.
# Current client emits A008 when mounting/switching a backpack and when
# equipping/taking off items. A009 is the response; A00A is the authoritative
# server notification in the corrected proto command ordering.
TGAME_ZN_REQ_PROP_OPERATION = 0xA008
TGAME_ZN_RES_PROP_OPERATION = 0xA009
TGAME_ZN_NTF_PROP_OPERATION = 0xA00A

PROP_OP_EQUIP = 0
PROP_OP_TAKEOFF = 1
PROP_OP_DROP = 2

# v73: manual Channels-tab path recovered directly from proto_c2zn.tdr.
# v82: creator-room path; A10B then full A105 MatchRoomInfo response.
TGAME_ZN_REQ_MATCHROOMLIST = 0xA100
TGAME_ZN_RES_MATCHROOMLIST = 0xA102
TGAME_ZN_REQ_CREATEMATCHROOM = 0xA10A
TGAME_ZN_RES_CREATEMATCHROOM = 0xA10B
# r15: live stock PH OnlineRequest_EnterRoomByRoomId request observed as A103.
TGAME_ZN_REQ_ENTERMATCHROOM = 0xA103
TGAME_ZN_RES_ENTERMATCHROOM = 0xA105
TGAME_ZN_NTF_ENTERMATCHROOM = 0xA106

# v135: live-observed lobby Exit/Leave Room request.
# Current PH client sends A107 body=u16 seat index (solo creator => 0x0000).
# Adjacent proto family and the earlier v99 dynamic-room branch identify:
#   A107 C2ZN_ReqLeaveMatchRoom
#   A108 ZN2C_ResLeaveMatchRoom
#   A109 ZN2C_NtfLeaveMatchRoom (for remaining room members)
TGAME_ZN_REQ_LEAVEMATCHROOM = 0xA107
TGAME_ZN_RES_LEAVEMATCHROOM = 0xA108
TGAME_ZN_NTF_LEAVEMATCHROOM = 0xA109

# v88: room camp/team switch, live-observed as A10D body=u8 Camp.
TGAME_ZN_REQ_CHANGEMATCHROOMCAMP = 0xA10D
TGAME_ZN_RES_CHANGEMATCHROOMCAMP = 0xA10E
TGAME_ZN_NTF_CHANGEMATCHROOMCAMP = 0xA10F

# v86/v108: live Room -> Ready/Start -> InMatch path.
# A110/A111/A112 are the adjacent SetMatchRoomReady family.  In this recovery
# branch we ACK A110 and record readiness, but the DS handoff is deliberately
# NOT fired by Ready.  The handoff occurs only when StartRoomAlloc/StartMatch
# transitions the room into match startup.
TGAME_ZN_REQ_SETMATCHROOMREADY = 0xA110
TGAME_ZN_RES_SETMATCHROOMREADY = 0xA111
TGAME_ZN_NTF_SETMATCHROOMREADY = 0xA112

# LATEJOIN-v3 TEST / recovered PH room-state values.
# A110 body=00 is an empty-TDR request. The same A110 is emitted again by the
# stock UI when the Ready button has become Cancel, so this test treats A110 as
# a state toggle and confirms both transitions through A112.
TGAME_PLAYERSTATE_UNREADY = 8
TGAME_PLAYERSTATE_READYTOMATCH = 9
TGAME_PLAYERSTATE_LOADINGMATCH = 11
TGAME_PLAYERSTATE_INMATCH = 12
TGAME_ZN_REQ_STARTMATCH = 0xA113
TGAME_ZN_RES_STARTMATCH = 0xA114
# Live-proven request emitted by OnlineRequest_JoinMatch. v26 disassembly
# recovered the compiled 0xA116 response handler and its full DSInfo layout.
TGAME_ZN_REQ_JOINMATCH = 0xA115
TGAME_ZN_RES_JOINMATCH = 0xA116
TGAME_ZN_REQ_QUITMATCH = 0xA117
TGAME_ZN_RES_QUITMATCH = 0xA118
TGAME_ZN_NTF_QUITMATCH = 0xA119
TGAME_ZN_NTF_STARTMATCH = 0xA11A
TGAME_ZN_REQ_SETINMATCH = 0xA11C
# Strongly inferred from the adjacent command family and TGame's
# HandleMessage_Notification_SetInMatch handler.  The live handler consumes
# the first field as a u16 seat index.
TGAME_ZN_NTF_SETINMATCH = 0xA11D
TGAME_ZN_REQ_SETGAMESETTINGS = 0xA11E

TGAME_ZN_REQ_ZONECHANNEL_LIST = 0xA132
TGAME_ZN_RES_ZONECHANNEL_LIST = 0xA133
TGAME_ZN_REQ_MAINCHNLLIST = 0xA355
TGAME_ZN_RES_MAINCHNLLIST = 0xA356
TGAME_ZN_REQ_CHANNEL_PING_VALUE = 0xA357
TGAME_ZN_RES_CHANNEL_PING_VALUE = 0xA358

# v125: this PH client emits A303 twice only after the normal lobby/main-channel
# UI has initialized.  Later branches recovered it as C2ZN_REQ_FRIENDSSTATUS.
# We use it only as a lobby-ready milestone; no social behavior is changed here.
TGAME_ZN_REQ_FRIEND_STATUS = 0xA303

TGAME_ZN_RES_HEARTBEAT = 0xFF10
TGAME_ZN_NTF_ZONE_HINTS = 0xFF13

# Nickname rename-card path.
# F301 is LIVE-PROVEN from the stock PH 1.0.0.24 client:
#   body = TDR string NewNickName
# F302 is a CONTROLLED TEST candidate based on the request/response pairing
# and the reflected callback:
#   OnTGOnlineDelegate_ChangeNickName(IntProperty ErrorCode, StrProperty NewNickName)
TGAME_ZN_REQ_CHANGE_NICKNAME = 0xF301
TGAME_ZN_RES_CHANGE_NICKNAME_TEST = 0xF302

# v160: statically recovered stock-PH action-card request/response pairs.
TGAME_ZN_REQ_CLEAR_MATCH_RECORD = 0xF303
TGAME_ZN_RES_CLEAR_MATCH_RECORD = 0xF304
TGAME_ZN_REQ_CLEAR_MATCH_WINLOSE = 0xF305
TGAME_ZN_RES_CLEAR_MATCH_WINLOSE = 0xF306

# v72: room-allocation family recovered from proto_c2zn.tdr and confirmed
# by the live 46-byte Start request emitted by the Match -> Start button.
TGAME_ZN_REQ_STARTROOMALLOC = 0xA3A0
TGAME_ZN_NTF_ENTERROOMALLOC = 0xA3A1
TGAME_ZN_RES_STARTROOMALLOC = 0xA3A2
TGAME_ZN_REQ_QUITROOMALLOC = 0xA3A3
TGAME_ZN_RES_QUITROOMALLOC = 0xA3A4
TGAME_ZN_NTF_STARTROOMALLOCMATCH = 0xA3A5
TGAME_ZN_NTF_QUITRAMATCH = 0xA3A6

TGAME_ZONE_PORT = 65006
TGAME_DS_PORT = 65007  # Python diagnostic DS remains here
TGAME_REAL_DS_PORT = 65008  # legacy AF<->plain-UE3 bridge endpoint
TGAME_DS_KEY = b"\x00" * 16  # live AFDEV listen-server dynamic key; exactly 16 bytes

# v133: Survival/PVE hands the stock client to the existing UE3 UDP bridge.
# The client connects to 127.0.0.1:65008; the bridge remains responsible for
# forwarding that gameplay traffic to the real AFDEV ?listen endpoint on 7777.
#
# This restores the packet-observation/translation point that v132 accidentally
# bypassed by advertising AFDEV:7777 directly in A11A.
# v165: recovered friend and private-chat command IDs.
TGAME_ZN_RES_FRIEND_STATUS = 0xA304
TGAME_ZN_REQ_ADD_FRIEND = 0xA305
TGAME_ZN_NTF_ADD_FRIEND = 0xA306
TGAME_ZN_C2S_RES_ADD_FRIEND = 0xA307
TGAME_ZN_S2C_RES_ADD_FRIEND = 0xA308
TGAME_ZN_REQ_DEL_FRIEND = 0xA309
TGAME_ZN_RES_DEL_FRIEND = 0xA30A
TGAME_ZN_REQ_QUERY_FRIEND = 0xA30F
TGAME_ZN_RES_QUERY_FRIEND = 0xA310
TGAME_ZN_NTF_FRIEND_LOGINOUT = 0xA326
TGAME_ZN_REQ_PLAYER_EXP = 0xA33A
TGAME_ZN_RES_PLAYER_EXP = 0xA33B
TGAME_ZN_NTF_READ_OFFLINE_MSG = 0xAB03
FRIEND_PRESENCE_INBOX_PATCH = "v171-presence-01-no-login-a308-seed"
FRIEND_PRESENCE_EDGE_PATCH = "v172-a326-edge-trigger-no-a303-loop"
FRIEND_PRESENCE_ENUM_PATCH = "v173-friend-presence-enum-1-2"
FRIEND_PRESENCE_SPLIT_PATCH = "v174-split-a304-status-a326-online-type"
FRIEND_PRESENCE_TRANSPORT_PATCH = "v175-a326-cmd02-notification"
FRIEND_ENRICHMENT_PATCH = "v170b-static-a326-a33b-friend-presence-exp"
TGAME_ZN_REQ_CHAT_P2P = 0xA405
TGAME_ZN_NTF_CHAT_P2P = 0xA406

TGAME_PVE_MODE_ID = 0x00002001  # legacy compatibility alias
TGAME_AFDEV_MODE_IDS = frozenset(AFDEV_MODE_IDS)
TGAME_PVE_DIRECT_AFDEV = os.environ.get(
    "AF_PVE_DIRECT_AFDEV", "1"
).strip().lower() not in ("0", "false", "off", "no")
TGAME_AFDEV_PORT = int(os.environ.get("AF_AFDEV_PORT", "65008"))


def tgame_parse_geo_app(plain):
    """Parse sequence + C2GEOPkg from decrypted cmd00 plaintext."""
    if len(plain) < 12:
        raise ValueError(f"short GEO plaintext {len(plain)}B")
    seq = struct.unpack(">I", plain[:4])[0]
    magic, cmd, head_len, body_len = struct.unpack(">HHHH", plain[4:12])
    if head_len < 8:
        raise ValueError(f"invalid GEO head_len={head_len}")
    app_total = 4 + head_len + body_len
    if app_total > len(plain):
        raise ValueError(
            f"truncated GEO packet head={head_len} body={body_len} plain={len(plain)}"
        )
    body_off = 4 + head_len
    return {
        "seq": seq,
        "magic": magic,
        "cmd": cmd,
        "head_len": head_len,
        "body_len": body_len,
        "body": plain[body_off:body_off + body_len],
    }


def _tdr_string_ascii(text):
    """Wire encoding used by GEO PingInfo.Domain.

    Runtime-verified against ProtocalHandler.dll's GEO2C_ResPingList decoder:
    the wire field is a big-endian u32 byte length (including the terminating
    NUL), followed by the NUL-terminated ASCII bytes.  The decoder consumes
    the length and stores only the string in the host-side structure.
    """
    raw = text.encode("ascii") + b"\x00"
    return struct.pack(">I", len(raw)) + raw

def tgame_build_geo_pinglist_response(seq, max_delay_ms=1000):
    """Build GEO2C_ResPingList with one local PingInfo entry.

    Static reconstruction from proto_c2geo.tdr:
      PingInfo internal size = 0x8C
      Group     : u32, offset 0x00
      Ipv4      : u32, offset 0x04
      Domain    : char[128], offset 0x08
      PingInMs  : u32, offset 0x88

    GEO2C_ResPingList:
      Result      : u16
      ServerCount : u16
      ServerArray : PingInfo[ServerCount]
      MaxDelayInMs: u32

    Runtime v60 verification in x32dbg:
      * ProtocalHandler's TDR decoder must see the GEO header (0x8202) at
        input offset 0; the 4-byte application sequence prefix must therefore
        NOT be serialized in this response plaintext.
      * Domain is encoded as u32_be(strlen+1) followed by NUL-terminated ASCII.
    """
    group = 0
    ipv4 = 0x7F000001       # semantic 127.0.0.1
    domain = "127.0.0.1"
    ping_ms = 0

    ping_info = (
        struct.pack(">I", group)
        + struct.pack(">I", ipv4)
        + _tdr_string_ascii(domain)
        + struct.pack(">I", ping_ms)
    )

    body = (
        struct.pack(">H", GEO_ERR_SUCC)   # success is 0x8B00, NOT zero
        + struct.pack(">H", 1)            # ServerCount
        + ping_info
        + struct.pack(">I", max_delay_ms & 0xffffffff)
    )
    # Domain="127.0.0.1\0" is 10 bytes plus a 4-byte BE length prefix.
    # PingInfo is therefore 26 bytes and the complete response body is 34
    # bytes (0x22).  This exact layout returned EAX=0 from the live TDR decoder.
    if len(ping_info) != 26 or len(body) != 34:
        raise AssertionError(
            f"unexpected GEO ping sizes: ping_info={len(ping_info)} body={len(body)}"
        )
    app = struct.pack(
        ">HHHH",
        TGAME_GEO_MAGIC,
        TGAME_GEO_RES_PINGLIST,
        8,
        len(body),
    ) + body
    # IMPORTANT: do not prepend seq here.  Runtime verification showed the
    # decoder must receive 82 02 ... at byte 0; prepending seq caused the
    # decoder to consume the sequence as struct data and fail with 0x82010402.
    # Keep seq in the signature only so older call sites remain compatible.
    return app


def tgame_build_cmd00_mode3(plain, key):
    enc = tgame_mode3_encrypt(plain, key)
    pkt = (
        b"\x55\x0e\x00\x04"
        + struct.pack(">I", 12)
        + struct.pack(">I", len(enc))
        + enc
    )
    return pkt, enc


def tgame_build_cmd02_mode3_body(plain, key):
    """Build server->client delivery using TPDU cmd02 with normal encrypted body.

    Static receive path finding:
      * cmd00 decrypted successfully but +12E9/default returns 0, so the
        higher wrapper does not enter the normal delivery path.
      * cmd02 is an explicit downlink branch that returns 1.
      * +754E0 still decrypts body payloads before +12E9, so keep the body
        as the normal mode3 application payload.

    Wire:
      55 0e 02 04
      BE32 head_len = 12
      BE32 body_len = len(mode3(app_plain))
      body = mode3(app_plain)
    """
    enc = tgame_mode3_encrypt(plain, key)
    pkt = (
        b"\x55\x0e\x02\x04"
        + struct.pack(">I", 12)
        + struct.pack(">I", len(enc))
        + enc
    )
    return pkt, enc


# ---------------------------------------------------------------------------
# v48: verified GEO -> ZONE application layer
# ---------------------------------------------------------------------------

def _v48_u8(v):  return struct.pack(">B", v & 0xff)
def _v48_i8(v):  return struct.pack(">b", v)
def _v48_u16(v): return struct.pack(">H", v & 0xffff)
def _v48_i16(v): return struct.pack(">h", v)
def _v48_u32(v): return struct.pack(">I", v & 0xffffffff)
def _v48_i32(v): return struct.pack(">i", v)
def _v48_u64(v): return struct.pack(">Q", v & 0xffffffffffffffff)
def _v48_i64(v): return struct.pack(">q", v)
def _v48_f64(v): return struct.pack(">d", float(v))


def _v48_tdr_string(s, maxlen=None):
    """TDR v11 type-21 string: raw NUL-terminated bytes, no length prefix."""
    b = s.encode("ascii") if isinstance(s, str) else bytes(s)
    if b.endswith(b"\x00"):
        b = b[:-1]
    if maxlen is not None and len(b) + 1 > maxlen:
        raise ValueError(f"TDR string too long ({len(b)+1}>{maxlen})")
    return b + b"\x00"


def _v50_geo_tdr_string(s, maxlen=None):
    """GEO string field: u32_be(strlen+1) followed by NUL-terminated bytes."""
    b = s.encode("ascii") if isinstance(s, str) else bytes(s)
    if b.endswith(b"\x00"):
        b = b[:-1]
    raw = b + b"\x00"
    if maxlen is not None and len(raw) > maxlen:
        raise ValueError(f"GEO TDR string too long ({len(raw)}>{maxlen})")
    return _v48_u32(len(raw)) + raw


def _v48_build_app(seq, magic, cmd, body):
    if len(body) > 0xffff:
        raise ValueError("application body exceeds u16 BodyLen")
    return (
        _v48_u32(seq)
        + _v48_u16(magic)
        + _v48_u16(cmd)
        + _v48_u16(8)
        + _v48_u16(len(body))
        + body
    )


def _v62_build_server_app(magic, cmd, body):
    """Server->TGame application payload.

    Runtime verification on GEO showed that downstream cmd00 plaintext starts
    directly at the TDR package header; the client's 4-byte app sequence is a
    client->server prefix and must not be prepended to server responses.
    """
    if len(body) > 0xffff:
        raise ValueError("application body exceeds u16 BodyLen")
    return (
        _v48_u16(magic)
        + _v48_u16(cmd)
        + _v48_u16(8)
        + _v48_u16(len(body))
        + body
    )


def _v48_parse_app(plain):
    if len(plain) < 12:
        raise ValueError(f"short app plaintext {len(plain)}B")
    seq = struct.unpack_from(">I", plain, 0)[0]
    magic, cmd, head_len, body_len = struct.unpack_from(">HHHH", plain, 4)
    if head_len < 8:
        raise ValueError(f"bad app HeadLen={head_len}")
    off = 4 + head_len
    if off + body_len > len(plain):
        raise ValueError(
            f"truncated app packet head={head_len} body={body_len} plain={len(plain)}"
        )
    return {
        "seq": seq, "magic": magic, "cmd": cmd,
        "head_len": head_len, "body_len": body_len,
        "body": plain[off:off + body_len],
    }


def _v48_parse_pinginfo(body, off):
    """Parse GEO PingInfo using the runtime-observed GEO string encoding.

    Wire:
      u32 Group | u32 Ipv4 | u32 DomainLen | Domain[DomainLen] | u32 PingInMs

    DomainLen includes the terminating NUL.  This is confirmed by the live
    C2GEO_ReqZoneList emitted after the v60 PingList response was accepted.
    """
    if off + 12 > len(body):
        raise ValueError("short PingInfo fixed prefix")
    group, addr = struct.unpack_from(">II", body, off)
    off += 8

    n = struct.unpack_from(">I", body, off)[0]
    off += 4
    if n < 1 or n > 128:
        raise ValueError(f"bad PingInfo.Domain wire length={n}")
    if off + n + 4 > len(body):
        raise ValueError("truncated PingInfo.Domain/PingInMs")

    raw_domain = body[off:off + n]
    off += n
    if not raw_domain.endswith(b"\x00"):
        raise ValueError("PingInfo.Domain missing terminal NUL")
    domain = raw_domain[:-1].decode("latin1", "replace")

    ping_ms = struct.unpack_from(">I", body, off)[0]
    off += 4
    iptxt = ".".join(str((addr >> sh) & 0xff) for sh in (24, 16, 8, 0))
    return {
        "group": group, "ipv4": iptxt, "domain": domain, "ping_ms": ping_ms,
        "domain_wire_len": n,
    }, off


def _v48_parse_geo_req_zonelist(body):
    if len(body) < 6:
        raise ValueError("short C2GEO_ReqZoneList")
    count = struct.unpack_from(">h", body, 0)[0]
    if count < 0 or count > 64:
        raise ValueError(f"bad ServerCount={count}")
    off = 2
    servers = []
    for _ in range(count):
        pi, off = _v48_parse_pinginfo(body, off)
        servers.append(pi)
    if off + 4 > len(body):
        raise ValueError("ReqZoneList missing MaxDelayInMs")
    max_delay = struct.unpack_from(">I", body, off)[0]
    off += 4
    return {
        "count": count, "servers": servers, "max_delay_ms": max_delay,
        "consumed": off, "body_len": len(body)
    }


def _v48_build_geo_zonelist(seq, port=TGAME_ZONE_PORT, ping_ms=0xfffffffe):
    """Build GEO2C_ResZoneList using the framing learned from the live GEO path.

    Like the runtime-verified PingList response, this GEO response starts at
    the 0x8202 GEO header (no 4-byte application sequence prefix).  ZoneInfo's
    Domain uses u32_be(strlen+1) followed by NUL-terminated ASCII, matching
    the C2GEO_ReqZoneList wire encoding observed from the real client.

    ``seq`` is retained only for call-site compatibility; it is not serialized.
    """
    # ZoneInfo:
    # u32 Ipv4 | GEO string Domain | u16 Port | i32 OnlineNum | u32 PingInMs |
    # u32 MainChannelId | i32 LoadExts[6]
    zone = (
        # ZoneInfo.Ipv4 is copied by TGame directly into sockaddr.sin_addr.
        # TDR decodes uint32 into little-endian host memory, so 127.0.0.1 must
        # be serialized numerically as 0x0100007F to leave bytes 7F 00 00 01
        # in the decoded object. 0x7F000001 produced 1.0.0.127 at connect().
        _v48_u32(0x0100007f)
        + _v50_geo_tdr_string("127.0.0.1", 128)
        + _v48_u16(port)
        + _v48_i32(1)
        + _v48_u32(ping_ms)
        + _v48_u32(1)
        + b"".join(_v48_i32(0) for _ in range(6))
    )
    body = (
        _v48_u16(GEO_ERR_SUCC)
        + _v48_i16(1)
        + zone
        + _v48_i16(1)  # EGEODecisionMethod_Sequential
    )
    # Old raw-string body was 0x3A.  The u32 DomainLen adds four bytes.
    if len(body) != 62:
        raise AssertionError(f"unexpected GEO ZoneList body len={len(body)}")
    return (
        _v48_u16(TGAME_GEO_MAGIC)
        + _v48_u16(TGAME_GEO_RES_ZONELIST)
        + _v48_u16(8)
        + _v48_u16(len(body))
        + body
    )


def _v48_parse_zn_login(body):
    if len(body) < 12:
        raise ValueError(f"short C2ZN_ReqLogin {len(body)}B")
    sub, pref, syscrc = struct.unpack_from(">III", body, 0)
    return {
        "sub_channel_id": sub,
        "preference_crc": pref,
        "system_crc": syscrc,
    }


def _v48_build_zn_login_response(
    seq, *, result=ZONE_ERR_SUCC, expose_wallet=True
):
    # ZN2C_ResLogin:
    # u16 Result | u32 MainChannelId | u32 SubChannelId | i64 ServerTime |
    # i32 TGamePoint | i32 GoldPoint | i16 FreePropCount
    wallet = _v140_wallet()
    ap = int(wallet["ap"]) if expose_wallet else 0
    gp = int(wallet["gp"]) if expose_wallet else 0
    body = (
        _v48_u16(result)
        + _v48_u32(1)
        + _v48_u32(1)
        + _v48_i64(int(time.time()))
        + _v48_i32(ap)  # TGamePoint / PH AP
        + _v48_i32(gp)  # GoldPoint / GP
        + _v48_i16(0)
    )
    if len(body) != 28:
        raise AssertionError(f"unexpected ZN login response body len={len(body)}")
    return _v62_build_server_app(TGAME_ZN_MAGIC, TGAME_ZN_RES_LOGIN, body)


def _v48_dt_zero():
    # TDR datetime is 8 bytes. Internal semantic layout remains unproven; zero
    # is deliberately used as the conservative unset value for this first pass.
    return b"\x00" * 8


# ---------------------------------------------------------------------------
# v109 PVE profile fix
#
# IMPORTANT: this file is based directly on the user's working v108 build.
# The A355/A356 main-channel and A132/A133 Local Subchannel paths are left
# unchanged.  Only PlayerInfo/A006 profile data is changed.
# ---------------------------------------------------------------------------

V109_UIN = 10001

# Known old-PH profile resources already recovered from the client catalog.
V109_ROLE_ITEM_ID = 100600       # Sofia / Claire female role root (catalog commodity 200593, Role1)
V109_BAG1_ITEM_ID = 100026       # default Package / backpack 1
V109_BAG2_ITEM_ID = 100063       # backpack 2 entitlement
V109_PRIMARY_ITEM_ID = 100497    # QBS09 shotgun (catalog commodity 200482, Primary slot)

# v127 starter Bag1 weapons.  These were already catalog-verified in v123;
# the v123 failure came from serializing SEVEN PropInfo rows into ONE A006 even
# though proto_c2zn declares PropInfo[5].  v127 keeps these items but publishes
# them in a legal multi-packet A006 stream.
V127_PISTOL_ITEM_ID = 100009     # USP
V127_MELEE_ITEM_ID = 100058      # MK4 / Jungle Bolo
V127_GRENADE_ITEM_ID = 100010    # M26Grenade / Frag Grenade

# v129 Sofia commodity 200593 default character bundle.
# The role root alone (100600 / internal name 'claire') renders the body but
# does not automatically grant/equip the bundle's default component props.
V129_SOFIA_HAND_ITEM_ID = 300121
V129_SOFIA_UPPER_ITEM_ID = 300122
V129_SOFIA_HAIR_ITEM_ID = 100602
# r20: live stock GetAllSkillItemInfos() proof:
# Strength = ItemID 100049, Rank 1, Owned=False, UnlockWay_1=1.
# PVE skill ownership is a real PlayerPropInfo, not PlayerInfo.SkillScore.
R20_STRENGTH_ITEM_ID = 100049

# PVE-SKILL-PROGRESSION-v2
# Stock TGOnlinePlayerData.GetAllSkillItemInfos() exposes these as the normal
# level-progression skills (UnlockWay_1 == 1). The client marks a skill owned
# only when a matching PlayerPropInfo exists.
#
# required_level is the level shown by the client. min_total_exp is the
# cumulative legacy Assault Fire / NZ EXP threshold for that level. We use the
# EXP threshold because Experience is the authoritative value persisted by the
# emulator and is what the stock client uses to derive PlayerLevel.
#
# Rank-127 / event-condition skills are deliberately NOT present here.
V170_PVE_LEVEL_SKILLS = (
    # item_id, required_level, min_total_exp, display name
    (100049, 1,      0, "Strength"),
    (100043, 3,    720, "Quick Fix"),
    (100313, 4,   1290, "Emergency surgery"),
    (100046, 5,   2080, "Last Stand"),
    (100185, 5,   2080, "Airborne"),
    (100186, 5,   2080, "Heavy Gunner"),
    (100189, 5,   2080, "Team Heal"),
    (100044, 6,   3100, "Wonder Drug"),
    (100050, 7,   4360, "Physical fitness"),
    (100314, 7,   4360, "Arms experts"),
    (100052, 8,   5870, "Mag-Master2"),
    (100319, 8,   5870, "Invincibility"),
    (100047, 9,   7640, "Invisibility"),
    (100317, 9,   7640, "Med Hacker"),
    (100053, 10,  9710, "Quickhand"),
    (100187, 10,  9710, "Quick Reload"),
    (100188, 10,  9710, "Runaway"),
    (100318, 16, 29550, "Kamikaze"),
    (100316, 18, 39470, "Skill-master"),
)
V170_PVE_LEVEL_SKILL_IDS = frozenset(
    int(row[0]) for row in V170_PVE_LEVEL_SKILLS
)

V109_ROLE_GID = ((V109_UIN & 0xffffffff) << 32) | 1
V109_BAG1_GID = ((V109_UIN & 0xffffffff) << 32) | 2
V109_BAG2_GID = ((V109_UIN & 0xffffffff) << 32) | 3
V109_PRIMARY_GID = ((V109_UIN & 0xffffffff) << 32) | 4
V127_PISTOL_GID = ((V109_UIN & 0xffffffff) << 32) | 5
V127_MELEE_GID = ((V109_UIN & 0xffffffff) << 32) | 6
V127_GRENADE_GID = ((V109_UIN & 0xffffffff) << 32) | 7
V129_SOFIA_HAND_GID = ((V109_UIN & 0xffffffff) << 32) | 8
V129_SOFIA_UPPER_GID = ((V109_UIN & 0xffffffff) << 32) | 9
V129_SOFIA_HAIR_GID = ((V109_UIN & 0xffffffff) << 32) | 10
R20_STRENGTH_GID = ((V109_UIN & 0xffffffff) << 32) | 11


# ---------------------------------------------------------------------------
# r13 identity-safe local multi-client wire projection
# ---------------------------------------------------------------------------

def _r13_wire_gid(gid, session_uin):
    gid = int(gid) & 0xFFFFFFFFFFFFFFFF
    session_uin = int(session_uin) & 0xFFFFFFFF
    hi = (gid >> 32) & 0xFFFFFFFF
    lo = gid & 0xFFFFFFFF
    if hi != (V109_UIN & 0xFFFFFFFF):
        return gid
    return (session_uin << 32) | lo


def _r13_canonical_gid(gid, session_uin):
    gid = int(gid) & 0xFFFFFFFFFFFFFFFF
    session_uin = int(session_uin) & 0xFFFFFFFF
    hi = (gid >> 32) & 0xFFFFFFFF
    lo = gid & 0xFFFFFFFF
    if hi != session_uin:
        return gid
    return ((V109_UIN & 0xFFFFFFFF) << 32) | lo


def _r13_project_prop(prop, session_uin):
    q = dict(prop)
    q["gid"] = _r13_wire_gid(q.get("gid", 0), session_uin)
    q["owner_gid"] = _r13_wire_gid(q.get("owner_gid", 0), session_uin)
    return q


def _r13_project_operation(op, session_uin):
    q = dict(op)
    q["subject_gid"] = _r13_wire_gid(q.get("subject_gid", 0), session_uin)
    q["target_gid"] = _r13_wire_gid(q.get("target_gid", 0), session_uin)
    return q


def _r13_canonicalize_operation(op, session_uin):
    q = dict(op)
    q["subject_gid"] = _r13_canonical_gid(q.get("subject_gid", 0), session_uin)
    q["target_gid"] = _r13_canonical_gid(q.get("target_gid", 0), session_uin)
    return q


def _r13_wire_current_role_gid(session_uin):
    return _r13_wire_gid(_v140_current_role_gid(), session_uin)


def _r13_identity_projection_selftest():
    b_uin = 10002
    canonical_role = ((V109_UIN & 0xFFFFFFFF) << 32) | 1
    b_role = (b_uin << 32) | 1
    assert _r13_wire_gid(canonical_role, b_uin) == b_role
    assert _r13_canonical_gid(b_role, b_uin) == canonical_role
    assert _r13_wire_gid(1, b_uin) == 1
    assert _r13_canonical_gid(1, b_uin) == 1
    return True


_R13_IDENTITY_PROJECTION_SELFTEST = _r13_identity_projection_selftest()

V109_LOC_PRIMARY = 0x00
V127_LOC_PISTOL = 0x01
V127_LOC_MELEE = 0x02
V127_LOC_GRENADE = 0x03
V109_LOC_ROLE1 = 0x0A
V109_LOC_BAG = 0x0C
V129_LOC_ROLE_COMPONENT = 0xFF   # catalog location=-1 serialized as uint8
V129_LOC_HAIR = 0x00             # Sofia hair item 100602 catalog location=0

V127_STARTER_WEAPON_SLOTS = {
    V109_PRIMARY_ITEM_ID: V109_LOC_PRIMARY,
    V127_PISTOL_ITEM_ID: V127_LOC_PISTOL,
    V127_MELEE_ITEM_ID: V127_LOC_MELEE,
    V127_GRENADE_ITEM_ID: V127_LOC_GRENADE,
}

# v115 role/backpack root fix:
# Live client A008 captures show BOTH the selected role and backpack
# entitlement props mounted under literal TargetGID/OwnerPropId = 1.
# The backpack entitlement props themselves
# being equipped with TargetGID/OwnerPropId = literal 1 and Location=Bag.
# M4A1 then points to Bag1's PropGID with Location=Primary.
#
# v109 incorrectly published Bag1/Bag2 with owner_gid=0.  That left the
# hierarchy half-built:
#
#   QBS09 -> Bag1
#   Bag1 -> NULL
#
# which is enough for the UI to label the weapon "[Bag 1]" but not enough
# for the equipped-slot/loadout view to mount that backpack naturally.
V110_BAG_MOUNT_OWNER = 1

V109_ITEM_HOURS = 24 * 365 * 10


def _v109_pack_prop_info(gid, item_id, owner_gid=0, location=V109_LOC_BAG,
                         durability=100, durability_max=100, gain_type=0,
                         avail_hours=V109_ITEM_HOURS, obtain_time=0,
                         uin=V109_UIN):
    """Pack one proto_c2zn.tdr PropInfo row (exactly 70 bytes)."""
    raw = (
        _v48_u64(uin)
        + _v48_u64(gid)
        + _v48_u32(item_id)
        + _v48_u64(0)                  # ResFlag
        + _v48_u32(1)                  # StackNum
        + _v48_u64(obtain_time)        # ObtainTime
        + _v48_u32(avail_hours)        # Validity
        + _v48_u32(durability)
        + _v48_u32(durability_max)
        + _v48_u64(owner_gid)
        + _v48_u8(location)
        + _v48_u32(avail_hours)
        + _v48_u32(0)                  # UseHour
        + _v48_u8(gain_type)
    )
    if len(raw) != 70:
        raise AssertionError(f"v109 PropInfo packed size {len(raw)} != 70")
    return raw


# v111 authoritative in-memory starter inventory.
# Reset on server restart; enough for the current single-player sandbox.
V111_INVENTORY = [
    {
        # v128: Sofia uses the same proven role GID/root/Role1 mount as the working role path
        # under literal owner/root 1 at Role1 (0x0A), exactly like the client
        # requests when the user manually equips the character.
        "gid": V109_ROLE_GID,
        "item_id": V109_ROLE_ITEM_ID,
        "owner_gid": V110_BAG_MOUNT_OWNER,
        "location": V109_LOC_ROLE1,
        "durability": 100,
        "durability_max": 100,
    },
    {
        "gid": V109_BAG1_GID,
        "item_id": V109_BAG1_ITEM_ID,
        "owner_gid": V110_BAG_MOUNT_OWNER,
        "location": V109_LOC_BAG,
        "durability": 0,
        "durability_max": 0,
    },
    {
        "gid": V109_BAG2_GID,
        "item_id": V109_BAG2_ITEM_ID,
        "owner_gid": V110_BAG_MOUNT_OWNER,
        "location": V109_LOC_BAG,
        "durability": 0,
        "durability_max": 0,
    },
    {
        # QBS09: catalog location=Primary(0), durable_max=0.
        "gid": V109_PRIMARY_GID,
        "item_id": V109_PRIMARY_ITEM_ID,
        "owner_gid": V109_BAG1_GID,
        "location": V109_LOC_PRIMARY,
        "durability": 0,
        "durability_max": 0,
    },
    {
        "gid": V127_PISTOL_GID,
        "item_id": V127_PISTOL_ITEM_ID,
        "owner_gid": V109_BAG1_GID,
        "location": V127_LOC_PISTOL,
        "durability": 100,
        "durability_max": 100,
    },
    {
        "gid": V127_MELEE_GID,
        "item_id": V127_MELEE_ITEM_ID,
        "owner_gid": V109_BAG1_GID,
        "location": V127_LOC_MELEE,
        "durability": 0,
        "durability_max": 0,
    },
    {
        "gid": V127_GRENADE_GID,
        "item_id": V127_GRENADE_ITEM_ID,
        "owner_gid": V109_BAG1_GID,
        "location": V127_LOC_GRENADE,
        "durability": 0,
        "durability_max": 0,
    },
    {
        # Sofia default hand component from commodity 200593.
        "gid": V129_SOFIA_HAND_GID,
        "item_id": V129_SOFIA_HAND_ITEM_ID,
        "owner_gid": V109_ROLE_GID,
        "location": V129_LOC_ROLE_COMPONENT,
        "durability": 0,
        "durability_max": 0,
    },
    {
        # Sofia default upper-body component from commodity 200593.
        "gid": V129_SOFIA_UPPER_GID,
        "item_id": V129_SOFIA_UPPER_ITEM_ID,
        "owner_gid": V109_ROLE_GID,
        "location": V129_LOC_ROLE_COMPONENT,
        "durability": 0,
        "durability_max": 0,
    },
    {
        # Sofia default hair component. v128 omitted this, which is why the
        # role root rendered bald even though the face/body were correct.
        "gid": V129_SOFIA_HAIR_GID,
        "item_id": V129_SOFIA_HAIR_ITEM_ID,
        "owner_gid": V109_ROLE_GID,
        "location": V129_LOC_HAIR,
        "durability": 0,
        "durability_max": 0,
    },
    {
        # r20: real Rank-1 PVE skill ownership.
        # GetAllSkillItemInfos() marks Strength owned when this PropInfo exists.
        "gid": R20_STRENGTH_GID,
        "item_id": R20_STRENGTH_ITEM_ID,
        "owner_gid": 0,
        "location": V109_LOC_BAG,
        "durability": 0,
        "durability_max": 0,
    },
]

# ===========================================================================
# v140 MALL / INVENTORY / CHARACTER STATE
# ===========================================================================
#
# Source evidence used:
#   * shipped UTGame.u OnlineRequest_* / OnTGOnlineDelegate_* signatures
#   * previously recovered proto_c2zn command IDs
#   * v106 commodity/item/price tables recovered from DefaultCommodityLibrary
#
# Core stock paths now implemented in this branch:
#   A361/A362  shop config hash
#   A503/A504  commodity-file check/ack
#   A505/A506  buy commodity
#   A50E       AP/TP balance query -> A00A UpdatePlayerProperty wallet update
#   A008/A009/A00A equip/takeoff/current-role transaction (already live)
#
# UTGame.u confirms:
#   OnlineRequest_SetCurrentRole(UniquePropId RolePropId)
#   OnlineRequest_EquipWithProp(OwnerPropId, PropId, Location)
#   OnlineRequest_TakeoffProp(PropId)
#   OnlineRequest_BuyCommodity(...)
#
# Live PH traces prove the role/equip/takeoff UI collapses onto A008
# C2ZN_ReqPropOperation, so v140 keeps that proven wire path rather than
# inventing separate command IDs.
#
# PH 1.0.0.24 live validation: A00A is schema-sensitive. The existing 19-byte
# PropOperation notification and the 36-byte UpdatePlayerProperty notification
# both route through A00A, with the body/TDR schema selecting the consumer.
TGAME_ZN_NTF_UPDATE_PLAYER_PROPERTY = 0xA00A
TGAME_ZN_REQ_ITEM_OPERATION = 0xA200
TGAME_ZN_RES_ITEM_OPERATION = 0xA201
# v160: OnlineRequest_UseFunctionCard(int,int) -> A347/A348.
TGAME_ZN_REQ_USE_CARD = 0xA347
TGAME_ZN_RES_USE_CARD = 0xA348
TGAME_ZN_REQ_SHOPCONFHASH = 0xA361
TGAME_ZN_RES_SHOPCONFHASH = 0xA362
TGAME_ZN_REQ_DROPPROP = 0xA363
TGAME_ZN_RES_DROPPROP = 0xA364
TGAME_ZN_NTF_COMMODITYINFO = 0xA365
TGAME_ZN_REQ_UPDATECOMMODITYFILE = 0xA503
TGAME_ZN_RES_UPDATECOMMODITYFILE = 0xA504
TGAME_ZN_REQ_BUYCOMMODITY = 0xA505
TGAME_ZN_RES_BUYCOMMODITY = 0xA506

# Consumer List purchase history (public issue #42).
# Direct compiled proto_c2zn metadata and live PH v1.0.0.24 verification:
#   ID_ZN2C_NTF_MONEYFLOW = 0xA367
#   MoneyType TP/AP=1, GP=2, MP=3; EMONEYFLOW_BUY=2.
TGAME_ZN_NTF_MONEYFLOW = 0xA367

TGAME_ZN_REQ_TP_BALANCE = 0xA50E

MONEYTYPE_TP = 1  # protocol TP == PH client AP
MONEYTYPE_GP = 2
MONEYTYPE_MP = 3
MONEYREASON_BUY = 2

PAY_GP = 1
PAY_TP = 2       # protocol TP == PH client AP
PAY_MP = 3
PAY_TPMP = 4
PAY_TPVOUCHER = 5

SHOP_ERR_SUCC = 0x8200
SHOP_ERR_FAIL = 0x8201
SHOP_ERR_COMMODITY_NOTEXIST = 0x8202
SHOP_ERR_COMMODITY_PERIODINVALID = 0x8208
SHOP_ERR_SHOPCART_EMPTY = 0x820A
SHOP_ERR_NOTENOUGHMONEY = 0x820B
SHOP_ERR_PAYTYPE_INVALID = 0x820C

# Stock EUPDATEPROPERTYFLAG_* values are bitmasks, not enum ordinals.
UPDATE_FLAG_TP = 0x01
UPDATE_FLAG_GP = 0x02
UPDATE_FLAG_EXP = 0x04
UPDATE_FLAG_PROP = 0x08
UPDATE_FLAG_MP = 0x10
UPDATE_REASON_BUY = 0x08  # retained pending the reason-value audit in issue #57
UPDATE_REASON_TP_BALANCE = 0x2A

V140_DEFAULT_AP = 100000
V140_DEFAULT_GP = 100000
V140_DEFAULT_MP = 100000
V140_ITEM_AVAIL_HOURS = 24 * 365 * 10
V140_MALL_STATE_PATH = Path(__file__).with_name("assaultfire_mall_state.json")

V140_SHOP_ITEM_MAP = {200001: 100001, 200002: 100002, 200003: 100003, 200004: 100004, 200005: 100005, 200006: 100006, 200007: 100007, 200008: 100008, 200009: 100009, 200010: 100010, 200011: 100011, 200012: 100012, 200019: 100016, 200020: 100027, 200021: 100032, 200022: 100033, 200026: 100035, 200027: 100036, 200028: 100037, 200029: 100069, 200031: 100041, 200032: 200001, 200033: 200002, 200034: 200003, 200035: 200004, 200036: 200005, 200037: 200006, 200038: 200007, 200039: 200008, 200040: 200009, 200041: 200010, 200042: 210001, 200043: 210002, 200044: 210003, 200045: 210004, 200046: 210005, 200047: 210006, 200048: 210007, 200049: 210008, 200050: 210009, 200051: 210010, 200052: 220001, 200053: 220002, 200054: 220003, 200055: 220004, 200056: 220005, 200057: 220006, 200058: 220007, 200059: 220008, 200060: 220009, 200061: 220010, 200062: 100054, 200064: 100056, 200065: 100057, 200066: 100058, 200067: 100059, 200068: 100060, 200069: 100061, 200070: 100062, 200071: 100064, 200074: 100068, 200075: 100017, 200076: 100018, 200077: 100019, 200082: 100024, 200083: 100025, 200086: 100031, 200087: 100028, 200088: 100014, 200089: 100070, 200090: 100071, 200091: 100072, 200092: 100073, 200093: 100074, 200094: 100075, 200095: 100076, 200096: 100077, 200097: 100078, 200098: 100079, 200099: 100080, 200100: 100081, 200101: 100082, 200102: 100083, 200103: 100084, 200104: 100085, 200105: 100086, 200106: 100087, 200107: 100088, 200108: 100089, 200109: 100090, 200110: 100091, 200111: 100092, 200112: 100093, 200113: 100094, 200114: 100095, 200115: 100096, 200116: 100097, 200117: 100098, 200118: 100099, 200119: 100100, 200120: 100101, 200121: 100102, 200122: 100103, 200123: 100104, 200124: 100105, 200128: 100111, 200129: 100112, 200130: 100113, 200131: 100114, 200132: 100115, 200133: 100116, 200134: 100117, 200135: 100118, 200136: 100119, 200137: 100120, 200138: 100121, 200139: 100122, 200140: 100123, 200141: 100124, 200142: 100125, 200143: 100126, 200144: 100127, 200145: 100128, 200146: 100129, 200147: 100133, 200148: 100134, 200159: 100143, 200161: 100145, 200162: 100146, 200163: 100147, 200164: 100148, 200165: 100149, 200166: 100150, 200169: 100153, 200170: 100154, 200171: 100155, 200172: 100156, 200173: 100157, 200174: 100158, 200175: 100159, 200176: 100160, 200177: 100161, 200178: 100162, 200179: 100163, 200180: 100164, 200181: 100165, 200182: 100166, 200183: 100167, 200184: 100168, 200185: 100169, 200186: 100170, 200187: 100171, 200188: 100172, 200190: 100174, 200191: 100175, 200192: 100176, 200193: 100177, 200194: 100178, 200195: 100179, 200196: 100180, 200197: 100181, 200198: 100182, 200199: 100183, 200200: 100184, 200201: 100196, 200202: 100197, 200203: 100198, 200204: 100199, 200205: 100200, 200206: 100201, 200207: 100202, 200208: 100203, 200210: 100205, 200211: 100206, 200212: 100207, 200213: 100208, 200215: 100210, 200217: 100141, 200218: 100214, 200219: 100211, 200220: 100212, 200221: 210011, 200222: 210012, 200223: 210013, 200224: 210014, 200225: 210015, 200226: 210016, 200227: 210017, 200228: 210018, 200229: 210019, 200230: 210020, 200231: 100215, 200232: 100216, 200233: 100217, 200234: 100220, 200235: 100221, 200236: 100222, 200237: 100223, 200238: 100224, 200244: 100230, 200246: 100232, 200247: 100238, 200248: 100239, 200249: 100240, 200250: 100241, 200251: 100242, 200252: 100243, 200253: 100244, 200254: 100245, 200255: 100246, 200263: 100259, 200264: 100260, 200265: 100261, 200266: 100262, 200267: 100263, 200268: 100264, 200269: 100265, 200270: 100266, 200271: 100267, 200272: 100268, 200273: 100269, 200274: 100270, 200275: 100271, 200276: 100272, 200279: 100275, 200280: 100276, 200281: 100277, 200282: 100278, 200283: 100279, 200287: 100283, 200288: 100284, 200291: 100287, 200293: 100289, 200295: 100291, 200296: 100292, 200297: 100293, 200298: 100294, 200302: 100295, 200303: 100296, 200304: 100297, 200305: 100298, 200310: 100303, 200311: 100304, 200312: 100305, 200314: 100307, 200316: 100309, 200317: 100310, 200318: 100311, 200319: 100312, 200320: 100320, 200321: 100321, 200322: 100326, 200323: 100327, 200324: 100328, 200325: 100329, 200326: 100330, 200327: 100331, 200328: 100332, 200329: 100333, 200330: 100334, 200331: 100336, 200332: 100337, 200336: 100341, 200342: 100347, 200343: 100348, 200344: 100349, 200345: 100350, 200346: 100351, 200347: 100352, 200348: 100353, 200349: 100354, 200350: 100355, 200351: 100356, 200352: 100357, 200353: 100358, 200356: 100365, 200357: 100366, 200360: 100369, 200361: 100370, 200362: 100371, 200363: 100372, 200364: 100373, 200368: 100377, 200371: 100380, 200372: 100381, 200373: 100382, 200375: 100384, 200378: 100390, 200380: 100392, 200388: 100399, 200389: 100400, 200390: 100401, 200397: 100408, 200399: 100410, 200414: 100425, 200417: 100428, 200421: 100432, 200426: 100437, 200439: 100450, 200440: 100451, 200441: 100452, 200444: 100455, 200446: 100457, 200447: 100458, 200448: 100459, 200457: 100470, 200459: 100472, 200460: 100473, 200465: 100478, 200466: 100479, 200467: 100480, 200468: 100481, 200469: 100482, 200470: 100483, 200471: 100484, 200481: 100496, 200482: 100497, 200483: 100479, 200484: 100479, 200485: 100498, 200486: 100499, 200489: 100500, 200490: 100503, 200491: 100504, 200492: 100505, 200493: 100506, 200494: 100507, 200495: 100508, 200496: 100509, 200497: 100510, 200498: 100511, 200499: 100502, 200500: 100512, 200501: 100513, 200505: 100521, 200506: 100522, 200507: 100523, 200508: 100524, 200509: 100525, 200512: 100245, 200513: 100244, 200514: 100241, 200515: 100310, 200516: 100527, 200517: 100528, 200518: 100529, 200519: 100531, 200520: 100532, 200521: 100533, 200522: 100181, 200523: 100259, 200524: 100534, 200526: 100536, 200527: 100537, 200537: 100547, 200539: 100549, 200540: 100550, 200541: 100551, 200549: 100337, 200550: 100206, 200552: 100561, 200553: 100563, 200554: 100564, 200555: 100565, 200556: 100568, 200557: 100178, 200558: 100283, 200559: 100568, 200560: 100569, 200562: 100567, 200563: 100566, 200565: 100573, 200566: 100574, 200567: 100581, 200569: 100588, 200570: 100589, 200571: 100590, 200573: 100587, 200574: 100591, 200575: 100575, 200576: 100576, 200578: 100578, 200580: 100580, 200581: 100592, 200582: 100593, 200583: 100594, 200584: 100595, 200588: 100517, 200592: 100599, 200593: 100600, 200594: 100603, 200595: 100604, 200596: 100605, 200597: 100606, 200598: 100607, 200599: 100608, 200600: 100609, 200601: 100610, 200602: 100611, 200605: 100614, 200607: 100616, 200608: 100617, 200609: 100618, 200611: 100620, 200612: 100621, 200614: 100623, 200615: 100624, 200616: 100599, 200619: 100626, 200620: 100627, 200622: 100629, 200623: 100627, 200626: 100638, 200627: 100639, 200628: 100640, 200630: 100642, 200631: 100643, 200632: 100646, 200633: 100647, 200634: 100623, 210001: 110001, 210002: 110002, 210006: 110004, 210007: 110005}
V140_SHOP_PRICES = {200001: ('GP', (18750,)), 200002: ('MP', (750, 1500, 4500)), 200003: ('GP', (14250,)), 200004: ('TP', (5, 9, 18, 30)), 200005: ('GP', (15000,)), 200006: ('GP', (18000,)), 200007: ('GP', (21750,)), 200008: ('MP', (750, 1500, 4500)), 200009: ('GP', (4000,)), 200010: ('GP', (4000,)), 200011: ('GP', (7500,)), 200012: ('GP', (6000,)), 200019: ('TP', (200,)), 200020: ('MP', (750, 1500, 4500)), 200021: ('TP', (5, 10, 20)), 200022: ('TP', (5, 10, 20)), 200026: ('GP', (8000,)), 200027: ('GP', (7500,)), 200028: ('GP', (10000,)), 200029: ('MP', (2500,)), 200031: ('GP', (21000,)), 200032: ('GP', (1,)), 200033: ('GP', (1,)), 200034: ('GP', (1,)), 200035: ('GP', (1,)), 200036: ('GP', (1,)), 200037: ('GP', (1,)), 200038: ('GP', (1,)), 200039: ('GP', (1,)), 200040: ('GP', (1,)), 200041: ('GP', (1,)), 200042: ('GP', (1,)), 200043: ('GP', (1,)), 200044: ('GP', (1,)), 200045: ('GP', (1,)), 200046: ('GP', (1,)), 200047: ('GP', (1,)), 200048: ('GP', (1,)), 200049: ('GP', (1,)), 200050: ('GP', (1,)), 200051: ('GP', (1,)), 200052: ('GP', (1,)), 200053: ('GP', (1,)), 200054: ('GP', (1,)), 200055: ('GP', (1,)), 200056: ('GP', (1,)), 200057: ('GP', (1,)), 200058: ('GP', (1,)), 200059: ('GP', (1,)), 200060: ('GP', (1,)), 200061: ('GP', (1,)), 200062: ('TP', (15,)), 200064: ('GP', (26250,)), 200065: ('TP', (7, 13, 35, 60)), 200066: ('TP', (6, 12, 24, 42)), 200067: ('TP', (9, 18, 49, 88)), 200068: ('TP', (13, 25, 68, 123)), 200069: ('GP', (25000,)), 200070: ('MP', (2500,)), 200071: ('MP', (750, 1500, 4500)), 200074: ('MP', (900, 1800, 5400)), 200075: ('TP', (5, 14, 25, 72)), 200076: ('TP', (5, 14, 25, 72)), 200077: ('TP', (5, 14, 25, 72)), 200082: ('TP', (5, 14, 25, 72)), 200083: ('TP', (5, 14, 25, 72)), 200086: ('TP', (5, 14, 25, 72)), 200087: ('GP', (25000,)), 200088: ('MP', (5000,)), 200089: ('GP', (13000,)), 200090: ('GP', (9000,)), 200091: ('GP', (12000,)), 200092: ('GP', (34500,)), 200093: ('GP', (18000,)), 200094: ('GP', (24000,)), 200095: ('GP', (23000,)), 200096: ('TP', (4, 8, 28, 37)), 200097: ('TP', (6, 12, 24, 42)), 200098: ('TP', (6, 12, 24, 42)), 200099: ('TP', (5, 9, 23, 42)), 200100: ('TP', (5, 14, 25, 72)), 200101: ('TP', (5, 14, 25, 72)), 200102: ('TP', (5, 14, 25, 72)), 200103: ('TP', (5, 14, 25, 72)), 200104: ('TP', (5, 14, 25, 72)), 200105: ('TP', (5, 14, 25, 72)), 200106: ('TP', (5, 14, 25, 72)), 200107: ('TP', (5, 14, 25, 72)), 200108: ('TP', (5, 14, 25, 72)), 200109: ('TP', (5, 14, 25, 72)), 200110: ('TP', (5, 14, 25, 72)), 200111: ('TP', (5, 14, 25, 72)), 200112: ('TP', (5, 14, 25, 72)), 200113: ('TP', (5, 14, 25, 72)), 200114: ('TP', (5, 14, 25, 72)), 200115: ('TP', (5, 14, 25, 72)), 200116: ('TP', (5, 14, 25, 72)), 200117: ('TP', (5, 14, 25, 72)), 200118: ('GP', (10000,)), 200119: ('GP', (10000,)), 200120: ('TP', (5, 14, 25, 72)), 200121: ('TP', (5, 14, 25, 72)), 200122: ('TP', (5, 14, 25, 72)), 200123: ('TP', (5, 14, 25, 72)), 200124: ('GP', (15500,)), 200128: ('GP', (11500,)), 200129: ('GP', (15000,)), 200130: ('TP', (4, 8, 21, 37)), 200131: ('GP', (25500,)), 200132: ('TP', (200,)), 200133: ('TP', (5, 14, 25, 72)), 200134: ('TP', (5, 14, 25, 72)), 200135: ('TP', (5, 14, 25, 72)), 200136: ('TP', (5, 14, 25, 72)), 200137: ('TP', (5, 14, 25, 72)), 200138: ('TP', (5, 14, 25, 72)), 200139: ('GP', (18000,)), 200140: ('MP', (2500,)), 200141: ('TP', (5, 14, 25, 72)), 200142: ('TP', (5, 14, 25, 72)), 200143: ('TP', (5, 14, 25, 72)), 200144: ('TP', (5, 14, 25, 72)), 200145: ('TP', (5, 14, 25, 72)), 200146: ('TP', (5, 14, 25, 72)), 200147: ('GP', (30000,)), 200148: ('MP', (450, 900, 2700)), 200159: ('TP', (8, 1500, 3000)), 200161: ('TP', (5, 14, 72, 116)), 200162: ('TP', (5, 14, 72, 116)), 200163: ('TP', (5, 14, 72, 116)), 200164: ('TP', (5, 14, 72, 116)), 200165: ('TP', (5, 14, 72, 116)), 200166: ('TP', (5, 14, 72, 116)), 200169: ('TP', (12, 29, 55)), 200170: ('GP', (16500,)), 200171: ('GP', (16500,)), 200172: ('GP', (16500,)), 200173: ('GP', (16500,)), 200174: ('GP', (16500,)), 200175: ('GP', (16500,)), 200176: ('GP', (16500,)), 200177: ('GP', (16500,)), 200178: ('GP', (16500,)), 200179: ('GP', (16500,)), 200180: ('GP', (16500,)), 200181: ('GP', (16500,)), 200182: ('GP', (16500,)), 200183: ('GP', (16500,)), 200184: ('GP', (16500,)), 200185: ('GP', (16500,)), 200186: ('GP', (16500,)), 200187: ('TP', (4, 9, 18, 35)), 200188: ('MP', (300, 1500, 4500)), 200190: ('TP', (1490, 4500, 7000, 8800)), 200191: ('TP', (4, 8, 16, 26)), 200192: ('MP', (400, 700, 1400, 2800)), 200193: ('TP', (4, 8, 16, 26)), 200194: ('TP', (6, 12, 24, 42)), 200195: ('GP', (13500,)), 200196: ('GP', (22500,)), 200197: ('TP', (250,)), 200198: ('TP', (0,)), 200199: ('TP', (300, 600, 1800, 3200)), 200200: ('TP', (150,)), 200201: ('TP', (200,)), 200202: ('TP', (4, 7, 19, 37)), 200203: ('GP', (22500,)), 200204: ('TP', (300,)), 200205: ('TP', (500,)), 200206: ('TP', (500,)), 200207: ('TP', (500,)), 200208: ('TP', (500,)), 200210: ('TP', (500, 1000, 3000, 5500)), 200211: ('TP', (4, 8, 16, 26)), 200212: ('TP', (4, 8, 21, 37)), 200213: ('MP', (750, 1500, 4500)), 200215: ('TP', (400, 800, 2400, 4500)), 200217: ('MP', (900, 1800, 5400)), 200218: ('GP', (42000,)), 200219: ('TP', (100, 800, 1400, 2500)), 200220: ('MP', (100, 300, 500, 800)), 200221: ('GP', (1,)), 200222: ('GP', (1,)), 200223: ('GP', (1,)), 200224: ('GP', (1,)), 200225: ('GP', (1,)), 200226: ('GP', (1,)), 200227: ('GP', (1,)), 200228: ('GP', (1,)), 200229: ('GP', (1,)), 200230: ('GP', (1,)), 200231: ('TP', (800, 1800, 2800, 3800)), 200232: ('GP', (5000,)), 200233: ('GP', (5000,)), 200234: ('MP', (750, 1500, 4500)), 200235: ('MP', (750, 1500, 4500)), 200236: ('TP', (3, 5, 12, 22)), 200237: ('TP', (5, 14, 25, 72)), 200238: ('TP', (5, 14, 25, 72)), 200244: ('TP', (0,)), 200246: ('GP', (25000,)), 200247: ('TP', (5, 9, 18, 30)), 200248: ('MP', (750, 1500, 4500)), 200249: ('TP', (500, 1000, 3000, 5500)), 200250: ('TP', (500, 1000, 3000, 5500)), 200251: ('TP', (4, 7, 19, 36)), 200252: ('TP', (4, 7, 19, 36)), 200253: ('TP', (4, 7, 19, 36)), 200254: ('TP', (0,)), 200255: ('TP', (0,)), 200263: ('TP', (4900,)), 200264: ('GP', (37500,)), 200265: ('GP', (19500,)), 200266: ('TP', (4, 8, 16, 26)), 200267: ('TP', (4, 8, 21, 21)), 200268: ('TP', (500,)), 200269: ('TP', (5, 14, 25, 72)), 200270: ('TP', (5, 14, 25, 72)), 200271: ('TP', (5, 14, 25, 72)), 200272: ('TP', (5, 14, 25, 72)), 200273: ('TP', (5, 14, 25, 72)), 200274: ('TP', (0,)), 200275: ('TP', (0,)), 200276: ('TP', (5, 14, 25, 72)), 200279: ('TP', (5, 14, 25, 72)), 200280: ('TP', (5, 14, 25, 72)), 200281: ('TP', (5, 14, 25, 72)), 200282: ('TP', (5, 14, 25, 72)), 200283: ('MP', (500,)), 200287: ('TP', (1500, 4500, 7000, 8800)), 200288: ('TP', (10, 17, 46, 83)), 200291: ('TP', (5, 10, 18, 30)), 200293: ('TP', (3200,)), 200295: ('GP', (22500,)), 200296: ('GP', (22500,)), 200297: ('GP', (21000,)), 200298: ('MP', (750, 1500, 4500)), 200302: ('MP', (450, 900, 2700)), 200303: ('TP', (5, 9, 18, 30)), 200304: ('MP', (400, 800, 2400)), 200305: ('MP', (900, 1800, 5400)), 200310: ('TP', (800,)), 200311: ('TP', (800,)), 200312: ('TP', (800,)), 200314: ('TP', (400, 800, 2400, 4500)), 200316: ('MP', (600, 1200, 2400, 4800)), 200317: ('TP', (500, 1000, 3000, 5500)), 200318: ('TP', (400, 800, 2400, 4500)), 200319: ('TP', (5000,)), 200320: ('TP', (5, 14, 25, 72)), 200321: ('TP', (5, 14, 25, 72)), 200322: ('TP', (1200, 3600, 6000, 7500)), 200323: ('TP', (1200, 3600, 6000, 7500)), 200324: ('TP', (1200, 3600, 6000, 7500)), 200325: ('TP', (1500, 4500, 7000, 8800)), 200326: ('TP', (1500, 4500, 7000, 8800)), 200327: ('TP', (1500, 4500, 7000, 8800)), 200328: ('GP', (8000,)), 200329: ('TP', (2900,)), 200330: ('TP', (0,)), 200331: ('MP', (900, 1800, 5400)), 200332: ('TP', (10, 27, 49, 80)), 200336: ('TP', (600,)), 200342: ('TP', (500,)), 200343: ('GP', (30000,)), 200344: ('TP', (10, 27, 74, 119)), 200345: ('TP', (10, 27, 74, 119)), 200346: ('TP', (10, 27, 74, 119)), 200347: ('TP', (10, 27, 74)), 200348: ('TP', (10, 27, 74, 119)), 200349: ('TP', (10, 27, 74, 119)), 200350: ('TP', (10, 27, 74)), 200351: ('TP', (10, 27, 74, 119)), 200352: ('TP', (10, 27, 74, 119)), 200353: ('TP', (10, 27, 74)), 200356: ('TP', (10, 17, 46, 83)), 200357: ('TP', (3, 6, 12, 28)), 200360: ('MP', (500,)), 200361: ('MP', (500,)), 200362: ('MP', (500,)), 200363: ('MP', (500,)), 200364: ('MP', (500,)), 200368: ('TP', (600,)), 200371: ('TP', (9, 17, 46, 83)), 200372: ('TP', (1500, 4500, 7000, 8800)), 200373: ('TP', (12, 29, 55)), 200375: ('TP', (12, 29, 55)), 200378: ('TP', (1200, 3600, 6500, 8200)), 200380: ('MP', (800, 1600, 3200, 6400)), 200388: ('TP', (1000,)), 200389: ('TP', (1000,)), 200390: ('TP', (1000,)), 200397: ('TP', (1000,)), 200399: ('TP', (2000,)), 200414: ('TP', (600,)), 200417: ('TP', (600,)), 200421: ('TP', (600,)), 200426: ('TP', (4, 8, 16, 26)), 200439: ('TP', (800,)), 200440: ('TP', (800,)), 200441: ('TP', (800,)), 200444: ('TP', (600,)), 200446: ('TP', (1500, 4600, 7200, 9000)), 200447: ('TP', (400,)), 200448: ('TP', (0,)), 200457: ('TP', (400,)), 200459: ('TP', (1300, 3900, 6800, 8800)), 200460: ('TP', (1000, 2500, 4500, 6500)), 200465: ('TP', (1200, 3600, 6500, 8200)), 200466: ('TP', (1800, 5500, 8500)), 200467: ('TP', (1700, 5200, 8200)), 200468: ('TP', (1900, 5600, 8800)), 200469: ('TP', (1800, 5000, 8800)), 200470: ('TP', (1200, 3500, 6000)), 200471: ('TP', (1500, 4500, 7500)), 200481: ('TP', (800, 2000, 4200, 7500)), 200482: ('TP', (1200, 3600, 7000, 9800)), 200483: ('TP', (0,)), 200484: ('TP', (0,)), 200485: ('TP', (1400, 4300, 6700, 8500)), 200486: ('TP', (1500, 4500, 7200, 9000)), 200489: ('TP', (600, 5000, 24000)), 200490: ('TP', (0,)), 200491: ('TP', (0,)), 200492: ('TP', (0,)), 200493: ('TP', (0,)), 200494: ('TP', (0,)), 200495: ('TP', (0,)), 200496: ('TP', (0,)), 200497: ('TP', (0,)), 200498: ('TP', (0,)), 200499: ('TP', (0,)), 200500: ('TP', (0,)), 200501: ('TP', (0,)), 200505: ('TP', (4, 8, 16, 26)), 200506: ('MP', (3000, 6000, 12000)), 200507: ('MP', (2500, 5000, 10000)), 200508: ('MP', (3750, 7500, 15000)), 200509: ('MP', (3000, 6000, 12000)), 200512: ('TP', (0,)), 200513: ('TP', (0,)), 200514: ('TP', (0,)), 200515: ('TP', (50, 135, 255)), 200516: ('TP', (800,)), 200517: ('TP', (800,)), 200518: ('TP', (500, 1000, 3000, 5500)), 200519: ('TP', (500, 1000, 3000, 5500)), 200520: ('TP', (500, 1000, 3000, 5500)), 200521: ('TP', (3200,)), 200522: ('TP', (3200,)), 200523: ('TP', (0,)), 200524: ('TP', (4, 8, 16, 26)), 200526: ('TP', (1500, 4500, 7000, 8800)), 200527: ('TP', (2000, 6000, 9900)), 200537: ('TP', (20, 40, 100, 150)), 200539: ('TP', (800,)), 200540: ('TP', (800,)), 200541: ('TP', (800,)), 200549: ('TP', (3100, 9500)), 200550: ('TP', (2200, 6900)), 200552: ('TP', (2900,)), 200553: ('TP', (20, 40, 100, 150)), 200554: ('TP', (20, 40, 100, 150)), 200555: ('TP', (1300, 4000, 6500, 8500)), 200556: ('TP', (1000, 3000)), 200557: ('TP', (1500, 2600, 8000)), 200558: ('TP', (1500, 2600, 8500)), 200559: ('TP', (0,)), 200560: ('TP', (6, 12, 24, 42)), 200562: ('MP', (1200,)), 200563: ('MP', (750,)), 200565: ('TP', (1000,)), 200566: ('TP', (1000,)), 200567: ('TP', (0,)), 200569: ('TP', (600,)), 200570: ('TP', (600,)), 200571: ('TP', (600,)), 200573: ('TP', (8000,)), 200574: ('TP', (800, 2400, 5200)), 200575: ('TP', (0,)), 200576: ('TP', (2000,)), 200578: ('TP', (3000,)), 200580: ('TP', (2000,)), 200581: ('TP', (0,)), 200582: ('TP', (1000, 3000, 6000, 8000)), 200583: ('GP', (100000,)), 200584: ('TP', (1200, 3600, 6500, 8200)), 200588: ('TP', (6000,)), 200592: ('TP', (0,)), 200593: ('TP', (0,)), 200594: ('TP', (1000, 2000, 6000, 12000)), 200595: ('TP', (26900,)), 200596: ('TP', (800, 2600, 5800, 8000)), 200597: ('TP', (800,)), 200598: ('TP', (800,)), 200599: ('TP', (800,)), 200600: ('TP', (800,)), 200601: ('TP', (800,)), 200602: ('TP', (800,)), 200605: ('TP', (0,)), 200607: ('TP', (0,)), 200608: ('GP', (30000,)), 200609: ('TP', (0,)), 200611: ('TP', (1300, 4000, 6800, 8800)), 200612: ('TP', (6, 12, 24, 42)), 200614: ('TP', (0,)), 200615: ('TP', (19900,)), 200616: ('TP', (6000,)), 200619: ('TP', (0,)), 200620: ('TP', (16900,)), 200622: ('TP', (6000,)), 200623: ('TP', (19900,)), 200626: ('TP', (1600, 4800, 7500, 9500)), 200627: ('TP', (800, 2400, 4000, 4800)), 200628: ('TP', (2000, 5000, 8000, 10000)), 200630: ('TP', (500, 1500, 2500, 3000)), 200631: ('GP', (50000,)), 200632: ('TP', (28800,)), 200633: ('TP', (0,)), 200634: ('TP', (500,)), 210001: ('GP', (10000,)), 210002: ('GP', (10000,)), 210006: ('TP', (4, 8, 16, 26)), 210007: ('TP', (4, 8, 21, 37))}
# Exact per-price-index validity hours from shop_catalog_real.json.
# Non-positive values are permanent/no-timer catalog sentinels.
V140_SHOP_AVAIL_HOURS = {
    200001: (-1,),
    200002: (72, 168, 720),
    200003: (-1,),
    200004: (3, 24, 72, 168),
    200005: (-1,),
    200006: (-1,),
    200007: (-1,),
    200008: (72, 168, 720),
    200009: (-1,),
    200010: (-1,),
    200011: (-1,),
    200012: (-1,),
    200019: (-1,),
    200020: (72, 168, 720),
    200021: (24, 72, 168),
    200022: (24, 72, 168),
    200026: (-1,),
    200027: (-1,),
    200028: (-1,),
    200029: (-1,),
    200031: (-1,),
    200032: (-1,),
    200033: (-1,),
    200034: (-1,),
    200035: (-1,),
    200036: (-1,),
    200037: (-1,),
    200038: (-1,),
    200039: (-1,),
    200040: (-1,),
    200041: (-1,),
    200042: (-1,),
    200043: (-1,),
    200044: (-1,),
    200045: (-1,),
    200046: (-1,),
    200047: (-1,),
    200048: (-1,),
    200049: (-1,),
    200050: (-1,),
    200051: (-1,),
    200052: (-1,),
    200053: (-1,),
    200054: (-1,),
    200055: (-1,),
    200056: (-1,),
    200057: (-1,),
    200058: (-1,),
    200059: (-1,),
    200060: (-1,),
    200061: (-1,),
    200062: (10,),
    200064: (-1,),
    200065: (3, 24, 72, 168),
    200066: (3, 24, 72, 168),
    200067: (3, 24, 72, 168),
    200068: (3, 24, 72, 168),
    200069: (-1,),
    200070: (-1,),
    200071: (72, 168, 720),
    200074: (72, 168, 720),
    200075: (24, 72, 168, 360),
    200076: (24, 72, 168, 360),
    200077: (24, 72, 168, 360),
    200082: (24, 72, 168, 360),
    200083: (24, 72, 168, 360),
    200086: (24, 72, 168, 360),
    200087: (-1,),
    200088: (-1,),
    200089: (-1,),
    200090: (-1,),
    200091: (-1,),
    200092: (-1,),
    200093: (-1,),
    200094: (-1,),
    200095: (-1,),
    200096: (3, 24, 72, 168),
    200097: (3, 24, 72, 168),
    200098: (3, 24, 72, 168),
    200099: (3, 24, 72, 168),
    200100: (24, 72, 168, 360),
    200101: (24, 72, 168, 360),
    200102: (24, 72, 168, 360),
    200103: (24, 72, 168, 360),
    200104: (24, 72, 168, 360),
    200105: (24, 72, 168, 360),
    200106: (24, 72, 168, 360),
    200107: (24, 72, 168, 360),
    200108: (24, 72, 168, 360),
    200109: (24, 72, 168, 360),
    200110: (24, 72, 168, 360),
    200111: (24, 72, 168, 360),
    200112: (24, 72, 168, 360),
    200113: (24, 72, 168, 360),
    200114: (24, 72, 168, 360),
    200115: (24, 72, 168, 360),
    200116: (24, 72, 168, 360),
    200117: (24, 72, 168, 360),
    200118: (-1,),
    200119: (-1,),
    200120: (24, 72, 168, 360),
    200121: (24, 72, 168, 360),
    200122: (24, 72, 168, 360),
    200123: (24, 72, 168, 360),
    200124: (-1,),
    200128: (-1,),
    200129: (-1,),
    200130: (3, 24, 72, 168),
    200131: (-1,),
    200132: (-1,),
    200133: (24, 72, 168, 360),
    200134: (24, 72, 168, 360),
    200135: (24, 72, 168, 360),
    200136: (24, 72, 168, 360),
    200137: (24, 72, 168, 360),
    200138: (24, 72, 168, 360),
    200139: (-1,),
    200140: (-1,),
    200141: (24, 72, 168, 360),
    200142: (24, 72, 168, 360),
    200143: (24, 72, 168, 360),
    200144: (24, 72, 168, 360),
    200145: (24, 72, 168, 360),
    200146: (24, 72, 168, 360),
    200147: (-1,),
    200148: (72, 168, 720),
    200159: (3, 720, 2160),
    200161: (3, 24, 168, 720),
    200162: (3, 24, 168, 720),
    200163: (3, 24, 168, 720),
    200164: (3, 24, 168, 720),
    200165: (3, 24, 168, 720),
    200166: (3, 24, 168, 720),
    200169: (24, 168, 360),
    200170: (-1,),
    200171: (-1,),
    200172: (-1,),
    200173: (-1,),
    200174: (-1,),
    200175: (-1,),
    200176: (-1,),
    200177: (-1,),
    200178: (-1,),
    200179: (-1,),
    200180: (-1,),
    200181: (-1,),
    200182: (-1,),
    200183: (-1,),
    200184: (-1,),
    200185: (-1,),
    200186: (-1,),
    200187: (3, 24, 72, 168),
    200188: (72, 168, 720),
    200190: (168, 720, 2160, 4320),
    200191: (3, 24, 72, 168),
    200192: (168, 168, 360, 720),
    200193: (3, 24, 72, 168),
    200194: (3, 24, 72, 168),
    200195: (-1,),
    200196: (-1,),
    200197: (-1,),
    200198: (-1, 200),
    200199: (72, 168, 720, 2160),
    200200: (-1,),
    200201: (-1,),
    200202: (3, 24, 72, 168),
    200203: (-1,),
    200204: (-1,),
    200205: (720,),
    200206: (720,),
    200207: (720,),
    200208: (720,),
    200210: (168, 720, 2160, 4320),
    200211: (3, 24, 72, 168),
    200212: (3, 24, 72, 168),
    200213: (72, 168, 720),
    200215: (72, 168, 720, 2160),
    200217: (72, 168, 720),
    200218: (-1,),
    200219: (2, 20, 40, 100),
    200220: (72, 168, 360, 720),
    200221: (-1,),
    200222: (-1,),
    200223: (-1,),
    200224: (-1,),
    200225: (-1,),
    200226: (-1,),
    200227: (-1,),
    200228: (-1,),
    200229: (-1,),
    200230: (-1,),
    200231: (168, 720, 2160, 4320),
    200232: (-1,),
    200233: (-1,),
    200234: (72, 168, 720),
    200235: (72, 168, 720),
    200236: (3, 24, 72, 168),
    200237: (24, 72, 168, 360),
    200238: (24, 72, 168, 360),
    200244: (72,),
    200246: (-1,),
    200247: (3, 24, 72, 168),
    200248: (72, 168, 720),
    200249: (72, 168, 720, 2160),
    200250: (72, 168, 720, 2160),
    200251: (3, 24, 72, 168),
    200252: (3, 24, 72, 168),
    200253: (3, 24, 72, 168),
    200254: (168,),
    200255: (168,),
    200263: (720,),
    200264: (-1,),
    200265: (-1,),
    200266: (3, 24, 72, 168),
    200267: (3, 24, 72, 168),
    200268: (720,),
    200269: (24, 72, 168, 360),
    200270: (24, 72, 168, 360),
    200271: (24, 72, 168, 360),
    200272: (24, 72, 168, 360),
    200273: (24, 72, 168, 360),
    200274: (0,),
    200275: (0,),
    200276: (24, 72, 168, 360),
    200279: (24, 72, 168, 360),
    200280: (24, 72, 168, 360),
    200281: (24, 72, 168, 360),
    200282: (24, 72, 168, 360),
    200283: (168,),
    200287: (168, 720, 2160, 4320),
    200288: (3, 24, 72, 168),
    200291: (3, 24, 72, 168),
    200293: (720,),
    200295: (-1,),
    200296: (-1,),
    200297: (-1,),
    200298: (72, 168, 720),
    200302: (72, 168, 720),
    200303: (3, 24, 72, 168),
    200304: (72, 168, 720),
    200305: (72, 168, 720),
    200310: (720,),
    200311: (720,),
    200312: (720,),
    200314: (72, 168, 720, 2160),
    200316: (72, 168, 360, 720),
    200317: (72, 168, 720, 2160),
    200318: (72, 168, 720, 2160),
    200319: (720,),
    200320: (24, 72, 168, 360),
    200321: (24, 72, 168, 360),
    200322: (168, 720, 2160, 4320),
    200323: (168, 720, 2160, 4320),
    200324: (168, 720, 2160, 4320),
    200325: (168, 720, 2160, 4320),
    200326: (168, 720, 2160, 4320),
    200327: (168, 720, 2160, 4320),
    200328: (-1,),
    200329: (4320,),
    200330: (0,),
    200331: (72, 168, 720),
    200332: (24, 72, 168, 360),
    200336: (720,),
    200342: (720,),
    200343: (-1,),
    200344: (24, 72, 168, 720),
    200345: (24, 72, 168, 720),
    200346: (24, 72, 168, 720),
    200347: (24, 72, 168),
    200348: (24, 72, 168, 720),
    200349: (24, 72, 168, 720),
    200350: (24, 72, 168),
    200351: (24, 72, 168, 720),
    200352: (24, 72, 168, 720),
    200353: (24, 72, 168),
    200356: (3, 24, 72, 168),
    200357: (3, 24, 72, 168),
    200360: (168,),
    200361: (168,),
    200362: (168,),
    200363: (168,),
    200364: (168,),
    200368: (720,),
    200371: (3, 24, 72, 168),
    200372: (168, 720, 2160, 4320),
    200373: (24, 72, 168),
    200375: (24, 72, 168),
    200378: (168, 720, 2160, 4320),
    200380: (72, 168, 360, 720),
    200388: (2160,),
    200389: (2160,),
    200390: (2160,),
    200397: (-1,),
    200399: (-1,),
    200414: (720,),
    200417: (720,),
    200421: (720,),
    200426: (3, 24, 72, 168),
    200439: (720,),
    200440: (720,),
    200441: (720,),
    200444: (720,),
    200446: (168, 720, 2160, 4320),
    200447: (-1,),
    200448: (0, -1),
    200457: (-1,),
    200459: (168, 720, 2160, 4320),
    200460: (168, 720, 2160, 4320),
    200465: (168, 720, 2160, 4320),
    200466: (168, 720, 2160),
    200467: (168, 720, 2160),
    200468: (168, 720, 2160),
    200469: (168, 720, 2160),
    200470: (168, 720, 2160),
    200471: (168, 720, 2160),
    200481: (168, 720, 2160, 4320),
    200482: (168, 720, 2160, 4320),
    200483: (0, -1),
    200484: (0, -1),
    200485: (168, 720, 2160, 4320),
    200486: (168, 720, 2160, 4320),
    200489: (1, 10, 50),
    200490: (0, -1),
    200491: (0, -1),
    200492: (0, -1),
    200493: (0, -1),
    200494: (0, -1),
    200495: (0, -1),
    200496: (0, -1),
    200497: (0, -1),
    200498: (0, -1),
    200499: (0, -1),
    200500: (0, -1),
    200501: (0, -1),
    200505: (3, 24, 72, 168),
    200506: (168, 360, 720),
    200507: (168, 360, 720),
    200508: (168, 360, 720),
    200509: (168, 360, 720),
    200512: (0,),
    200513: (0,),
    200514: (0,),
    200515: (24, 72, 168),
    200516: (720,),
    200517: (720,),
    200518: (72, 168, 720, 2160),
    200519: (72, 168, 720, 2160),
    200520: (72, 168, 720, 2160),
    200521: (168,),
    200522: (168,),
    200523: (0, -1),
    200524: (3, 24, 72, 168),
    200526: (168, 720, 2160, 4320),
    200527: (168, 720, 2160),
    200537: (3, 24, 72, 168),
    200539: (720,),
    200540: (720,),
    200541: (720,),
    200549: (168, 720),
    200550: (168, 720),
    200552: (4320,),
    200553: (3, 24, 72, 168),
    200554: (3, 24, 72, 168),
    200555: (168, 720, 2160, 4320),
    200556: (168, 720),
    200557: (72, 168, 720),
    200558: (72, 168, 720),
    200559: (0, -1),
    200560: (3, 24, 72, 168),
    200562: (1,),
    200563: (1,),
    200565: (2160,),
    200566: (2160,),
    200567: (0,),
    200569: (720,),
    200570: (720,),
    200571: (720,),
    200573: (-1,),
    200574: (168, 720, 2160),
    200575: (0,),
    200576: (-1,),
    200578: (-1,),
    200580: (-1,),
    200581: (2160,),
    200582: (168, 720, 2160, 4320),
    200583: (-1,),
    200584: (168, 720, 2160, 4320),
    200588: (-1,),
    200592: (0,),
    200593: (0,),
    200594: (72, 168, 720, 4320),
    200595: (-1,),
    200596: (168, 720, 2160, 4320),
    200597: (720,),
    200598: (720,),
    200599: (720,),
    200600: (720,),
    200601: (720,),
    200602: (720,),
    200605: (0,),
    200607: (0,),
    200608: (-1,),
    200609: (0,),
    200611: (168, 720, 2160, 4320),
    200612: (3, 24, 72, 168),
    200614: (0,),
    200615: (-1,),
    200616: (-1,),
    200619: (0,),
    200620: (-1,),
    200622: (-1,),
    200623: (-1,),
    200626: (168, 720, 2160, 4320),
    200627: (168, 720, 2160, 4320),
    200628: (168, 720, 2160, 4320),
    200630: (168, 720, 2160, 4320),
    200631: (-1,),
    200632: (-1,),
    200633: (0,),
    200634: (168,),
    210001: (-1,),
    210002: (-1,),
    210006: (3, 24, 72, 168),
    210007: (3, 24, 72, 168),
}

V140_ITEM_DEFAULT_LOCATIONS = {100001: 0, 100002: 0, 100003: 0, 100004: 0, 100005: 1, 100006: 0, 100007: 0, 100008: 0, 100009: 1, 100010: 3, 100011: 4, 100012: 5, 100014: 10, 100016: 11, 100017: 0, 100018: 1, 100019: 2, 100023: 0, 100024: 1, 100025: 2, 100027: 0, 100028: 11, 100029: 0, 100030: 1, 100031: 2, 100032: 3, 100033: 4, 100035: 12, 100036: 12, 100037: 12, 100041: 0, 100054: -1, 100056: 0, 100057: 0, 100058: 2, 100059: 13, 100060: 14, 100061: 10, 100062: 10, 100064: 0, 100068: 0, 100069: 11, 100070: 0, 100071: 0, 100072: 1, 100073: 0, 100074: 0, 100075: 0, 100076: 0, 100077: 2, 100078: 2, 100079: 3, 100080: 0, 100081: 1, 100082: 1, 100083: 1, 100084: 1, 100085: 1, 100086: 1, 100087: 1, 100088: 1, 100089: 0, 100090: 0, 100091: 0, 100092: 0, 100093: 2, 100094: 2, 100095: 2, 100096: 2, 100097: 2, 100098: 2, 100099: 0, 100100: 0, 100101: 2, 100102: 2, 100103: 0, 100104: 1, 100105: 0, 100111: 0, 100112: 0, 100113: 0, 100114: 0, 100115: 10, 100116: 1, 100117: 1, 100118: 0, 100119: 0, 100120: 2, 100121: 2, 100122: 0, 100123: 11, 100124: 1, 100125: 1, 100126: 0, 100127: 0, 100128: 2, 100129: 2, 100130: 0, 100131: 0, 100133: 0, 100134: 1, 100141: 0, 100143: 18, 100145: -1, 100146: -1, 100147: -1, 100148: -1, 100149: -1, 100150: -1, 100153: 10, 100154: 9, 100155: 9, 100156: 9, 100157: 9, 100158: 9, 100159: 9, 100160: 9, 100161: 9, 100162: 9, 100163: 9, 100164: 9, 100165: 9, 100166: 9, 100167: 9, 100168: 9, 100169: 9, 100170: 9, 100171: 0, 100172: 0, 100174: 0, 100175: 0, 100176: 0, 100177: 0, 100178: 0, 100179: 1, 100180: 2, 100181: -1, 100182: -1, 100183: 15, 100184: 10, 100196: -1, 100197: 17, 100198: 0, 100199: 11, 100200: 0, 100201: 1, 100202: 1, 100203: 2, 100205: 8, 100206: 0, 100207: 1, 100208: 2, 100210: -1, 100211: 19, 100212: 3, 100214: 0, 100215: 12, 100216: 10, 100217: 11, 100218: 1, 100219: 1, 100220: 0, 100221: 0, 100222: 1, 100223: 2, 100224: 0, 100226: 0, 100230: 1, 100232: 0, 100238: 0, 100239: 2, 100240: 28, 100241: 30, 100242: 25, 100243: 26, 100244: 27, 100245: 20, 100246: 21, 100259: 3, 100260: 0, 100261: 0, 100262: 0, 100263: 1, 100264: 0, 100265: 0, 100266: 1, 100267: 0, 100268: 1, 100269: 2, 100270: 10, 100271: 11, 100272: 1, 100273: 0, 100275: 1, 100276: 0, 100277: 2, 100278: 1, 100279: 0, 100283: 0, 100284: 0, 100287: 0, 100289: 2, 100291: 0, 100292: 0, 100293: 0, 100294: 0, 100295: 1, 100296: 0, 100297: 0, 100298: 0, 100303: 2, 100304: 1, 100305: 0, 100307: 3, 100309: 0, 100310: 23, 100311: 24, 100312: 3, 100320: 0, 100321: 0, 100322: 0, 100323: 0, 100324: 0, 100325: 0, 100326: 0, 100327: 0, 100328: 0, 100329: 0, 100330: 0, 100331: 0, 100332: 9, 100333: 10, 100334: 11, 100335: 0, 100336: 0, 100337: 0, 100341: 0, 100347: 12, 100348: 0, 100349: 9, 100350: 9, 100351: 9, 100352: 9, 100353: 9, 100354: 9, 100355: 9, 100356: 9, 100357: 9, 100358: 9, 100365: 0, 100366: 0, 100369: 2, 100370: 1, 100371: 0, 100372: 2, 100373: 1, 100377: 0, 100380: 0, 100381: 0, 100382: 11, 100384: 10, 100387: 0, 100389: 0, 100390: 2, 100392: 0, 100399: 9, 100400: 9, 100401: 9, 100408: 9, 100410: 9, 100425: 2, 100428: 2, 100432: 1, 100437: 0, 100450: 2, 100451: 1, 100452: 0, 100455: 2, 100457: 0, 100458: 10, 100459: 3, 100460: 0, 100470: 11, 100472: 0, 100473: 3, 100478: 0, 100479: 0, 100480: 0, 100481: 0, 100482: 0, 100483: 1, 100484: 2, 100490: 0, 100496: 0, 100497: 0, 100498: 0, 100499: 0, 100500: -1, 100502: 0, 100503: 0, 100504: 0, 100505: 0, 100506: 0, 100507: 0, 100508: 0, 100509: 0, 100510: 0, 100511: 0, 100512: 1, 100513: 0, 100517: -1, 100521: 0, 100522: 0, 100523: 0, 100524: 0, 100525: 0, 100527: 2, 100528: 0, 100529: 1, 100530: 2, 100531: 31, 100532: 32, 100533: 33, 100534: 0, 100536: 0, 100537: 34, 100547: 0, 100549: 0, 100550: 1, 100551: 2, 100561: 11, 100562: 0, 100563: 0, 100564: 0, 100565: 0, 100566: -1, 100567: -1, 100568: 35, 100569: 1, 100573: 9, 100574: 9, 100575: -1, 100576: -1, 100578: -1, 100580: -1, 100581: 0, 100587: -1, 100588: 0, 100589: 1, 100590: 2, 100591: 36, 100592: 37, 100593: 0, 100594: 0, 100595: 2, 100599: 11, 100600: 10, 100601: 0, 100602: 0, 100603: 0, 100604: 0, 100605: 1, 100606: 0, 100607: 1, 100608: 2, 100609: 0, 100610: 1, 100611: 2, 100614: -1, 100616: -1, 100617: 0, 100618: 0, 100620: 0, 100621: 0, 100623: 10, 100624: 0, 100626: 11, 100627: 1, 100629: 39, 100638: 0, 100639: 0, 100640: 0, 100642: 1, 100643: 2, 100645: 0, 100646: 0, 100647: 2, 100648: 0, 100649: 1, 100928: 12, 110001: 0, 110002: 0, 110004: 0, 110005: 2, 200001: 12, 200002: 12, 200003: 12, 200004: 12, 200005: 12, 200006: 12, 200007: 12, 200008: 12, 200009: 12, 200010: 12, 210001: 12, 210002: 12, 210003: 12, 210004: 12, 210005: 12, 210006: 12, 210007: 12, 210008: 12, 210009: 12, 210010: 12, 210011: 12, 210012: 12, 210013: 12, 210014: 12, 210015: 12, 210016: 12, 210017: 12, 210018: 12, 210019: 12, 210020: 12, 220001: 12, 220002: 12, 220003: 12, 220004: 12, 220005: 12, 220006: 12, 220007: 12, 220008: 12, 220009: 12, 220010: 12, 300002: -1, 300003: -1, 300012: -1, 300013: -1, 300017: -1, 300018: -1, 300022: -1, 300023: -1, 300027: -1, 300028: -1, 300032: -1, 300033: -1, 300037: -1, 300038: -1, 300042: -1, 300043: -1, 300047: -1, 300048: -1, 300052: -1, 300053: -1, 300057: -1, 300058: -1, 300062: -1, 300063: -1, 300067: -1, 300068: -1, 300072: -1, 300073: -1, 300077: -1, 300078: -1, 300082: -1, 300083: -1, 300087: -1, 300088: -1, 300092: -1, 300093: -1, 300102: -1, 300103: -1, 300107: -1, 300108: -1, 300112: -1, 300113: -1, 300117: -1, 300118: -1, 300119: -1, 300120: -1, 300121: -1, 300122: -1, 300123: -1, 300124: -1, 300125: -1, 300126: -1}
V140_COMMODITY_BUNDLES = {200001: (100001,), 200002: (100002,), 200003: (100003,), 200004: (100004,), 200005: (100005,), 200006: (100006,), 200007: (100007,), 200008: (100008,), 200009: (100009,), 200010: (100010,), 200011: (100011,), 200012: (100012,), 200019: (100016, 300012, 300013, 100023), 200020: (100027,), 200021: (100032,), 200022: (100033,), 200026: (100035,), 200027: (100036,), 200028: (100037,), 200029: (100069, 300032, 300033, 100322), 200031: (100041,), 200032: (200001,), 200033: (200002,), 200034: (200003,), 200035: (200004,), 200036: (200005,), 200037: (200006,), 200038: (200007,), 200039: (200008,), 200040: (200009,), 200041: (200010,), 200042: (210001,), 200043: (210002,), 200044: (210003,), 200045: (210004,), 200046: (210005,), 200047: (210006,), 200048: (210007,), 200049: (210008,), 200050: (210009,), 200051: (210010,), 200052: (220001,), 200053: (220002,), 200054: (220003,), 200055: (220004,), 200056: (220005,), 200057: (220006,), 200058: (220007,), 200059: (220008,), 200060: (220009,), 200061: (220010,), 200062: (100054,), 200064: (100056,), 200065: (100057,), 200066: (100058,), 200067: (100059,), 200068: (100060,), 200069: (100061, 300022, 300023, 100325), 200070: (100062, 300027, 300028), 200071: (100064,), 200074: (100068,), 200075: (100017,), 200076: (100018,), 200077: (100019,), 200082: (100024,), 200083: (100025,), 200086: (100031,), 200087: (100028, 100029, 100030, 300017, 300018), 200088: (100014, 300002, 300003), 200089: (100070,), 200090: (100071,), 200091: (100072,), 200092: (100073,), 200093: (100074,), 200094: (100075,), 200095: (100076,), 200096: (100077,), 200097: (100078,), 200098: (100079,), 200099: (100080,), 200100: (100081,), 200101: (100082,), 200102: (100083,), 200103: (100084,), 200104: (100085,), 200105: (100086,), 200106: (100087,), 200107: (100088,), 200108: (100089,), 200109: (100090,), 200110: (100091,), 200111: (100092,), 200112: (100093,), 200113: (100094,), 200114: (100095,), 200115: (100096,), 200116: (100097,), 200117: (100098,), 200118: (100099,), 200119: (100100,), 200120: (100101,), 200121: (100102,), 200122: (100103,), 200123: (100104,), 200124: (100105,), 200128: (100111,), 200129: (100112,), 200130: (100113,), 200131: (100114,), 200132: (100115, 300037, 300038, 100130), 200133: (100116,), 200134: (100117,), 200135: (100118,), 200136: (100119,), 200137: (100120,), 200138: (100121,), 200139: (100122,), 200140: (100123, 300042, 300043, 100131), 200141: (100124,), 200142: (100125,), 200143: (100126,), 200144: (100127,), 200145: (100128,), 200146: (100129,), 200147: (100133,), 200148: (100134,), 200159: (100143,), 200161: (100145,), 200162: (100146,), 200163: (100147,), 200164: (100148,), 200165: (100149,), 200166: (100150,), 200169: (100153, 300047, 300048, 100226), 200172: (100156,), 200173: (100157,), 200174: (100158,), 200175: (100159,), 200176: (100160,), 200177: (100161,), 200178: (100162,), 200179: (100163,), 200180: (100164,), 200181: (100165,), 200182: (100166,), 200183: (100167,), 200184: (100168,), 200185: (100169,), 200186: (100170,), 200187: (100171,), 200188: (100172,), 200190: (100174,), 200191: (100175,), 200192: (100176,), 200193: (100177,), 200194: (100178,), 200195: (100179,), 200196: (100180,), 200197: (100181,), 200198: (100182,), 200199: (100183,), 200200: (100184, 300052, 300053), 200201: (100196,), 200202: (100197,), 200203: (100198,), 200204: (100199, 300057, 300058), 200205: (100200,), 200206: (100201,), 200207: (100202,), 200208: (100203,), 200210: (100205,), 200211: (100206,), 200212: (100207,), 200213: (100208,), 200215: (100210,), 200217: (100141,), 200218: (100214,), 200219: (100211,), 200220: (100212,), 200221: (210011,), 200222: (210012,), 200223: (210013,), 200224: (210014,), 200225: (210015,), 200226: (210016,), 200227: (210017,), 200228: (210018,), 200229: (210019,), 200230: (210020,), 200231: (100215,), 200232: (100216, 300062, 300063, 100218, 100323), 200233: (100217, 300067, 300068, 100219, 100324), 200234: (100220,), 200235: (100221,), 200236: (100222,), 200237: (100223,), 200238: (100224,), 200244: (100230,), 200246: (100232,), 200247: (100238,), 200248: (100239,), 200249: (100240,), 200250: (100241,), 200251: (100242,), 200252: (100243,), 200253: (100244,), 200254: (100245,), 200255: (100246,), 200263: (100259,), 200264: (100260,), 200265: (100261,), 200266: (100262,), 200267: (100263,), 200268: (100264,), 200269: (100265,), 200270: (100266,), 200271: (100267,), 200272: (100268,), 200273: (100269,), 200274: (100270, 300072, 300073), 200275: (100271, 300077, 300078, 100273), 200276: (100272,), 200279: (100275,), 200280: (100276,), 200281: (100277,), 200282: (100278,), 200283: (100279,), 200287: (100283,), 200288: (100284,), 200291: (100287,), 200293: (100289,), 200295: (100291,), 200296: (100292,), 200297: (100293,), 200298: (100294,), 200302: (100295,), 200303: (100296,), 200304: (100297,), 200305: (100298,), 200310: (100303,), 200311: (100304,), 200312: (100305,), 200314: (100307,), 200316: (100309,), 200317: (100310,), 200318: (100311,), 200319: (100312,), 200320: (100320,), 200321: (100321,), 200322: (100326,), 200323: (100327,), 200324: (100328,), 200325: (100329,), 200326: (100330,), 200327: (100331,), 200328: (100332,), 200329: (100333, 300082, 300083, 100335), 200330: (100334, 300087, 300088), 200331: (100336,), 200332: (100337,), 200336: (100341,), 200342: (100347,), 200343: (100348,), 200344: (100349,), 200345: (100350,), 200346: (100351,), 200347: (100352,), 200348: (100353,), 200349: (100354,), 200350: (100355,), 200351: (100356,), 200352: (100357,), 200353: (100358,), 200356: (100365,), 200357: (100366,), 200360: (100369,), 200361: (100370,), 200363: (100372,), 200364: (100373,), 200368: (100377,), 200371: (100380,), 200372: (100381,), 200373: (100382, 300092, 300093, 100387), 200375: (100384, 300102, 300103, 100389, 100928), 200378: (100390,), 200380: (100392,), 200388: (100399,), 200389: (100400,), 200390: (100401,), 200397: (100408,), 200399: (100410,), 200414: (100425,), 200417: (100428,), 200421: (100432,), 200426: (100437,), 200439: (100450,), 200440: (100451,), 200441: (100452,), 200444: (100455,), 200446: (100457,), 200447: (100458, 300107, 300108, 100460, 100530), 200448: (100459,), 200457: (100470, 300112, 300113, 100490), 200459: (100472,), 200460: (100473,), 200465: (100478,), 200466: (100479,), 200467: (100480,), 200468: (100481,), 200469: (100482,), 200470: (100483,), 200471: (100484,), 200481: (100496,), 200482: (100497,), 200483: (100479, 100480, 100481, 100482, 100483, 100484), 200484: (100479, 100480, 100481, 100482, 100483, 100484), 200485: (100498,), 200486: (100499,), 200489: (100500,), 200490: (100503,), 200491: (100504,), 200492: (100505,), 200493: (100506,), 200494: (100507,), 200495: (100508,), 200496: (100509,), 200497: (100510,), 200498: (100511,), 200499: (100502,), 200500: (100512,), 200501: (100513,), 200505: (100521,), 200506: (100522,), 200507: (100523,), 200508: (100524,), 200509: (100525,), 200512: (100245, 100246), 200513: (100244, 100240, 100183, 100205), 200514: (100241, 100210, 100242, 100243), 200515: (100310, 100311, 100307), 200516: (100527,), 200517: (100528,), 200518: (100529,), 200519: (100531,), 200520: (100532,), 200521: (100533,), 200522: (100181, 100182, 100196, 100352), 200523: (100259, 100238, 100060, 100357), 200524: (100534,), 200526: (100536,), 200527: (100537,), 200537: (100547,), 200539: (100549,), 200540: (100550,), 200541: (100551,), 200549: (100337, 100032, 100033, 100079), 200550: (100206, 100263, 100078), 200552: (100561, 300117, 300118, 100562), 200553: (100563,), 200554: (100564,), 200555: (100565,), 200556: (100568,), 200557: (100178, 100207, 100077), 200558: (100283, 100079, 100222), 200559: (100568, 100531, 100532, 100533, 100310, 100311, 100307), 200560: (100569,), 200562: (100567,), 200563: (100566,), 200566: (100574,), 200567: (100581,), 200569: (100588,), 200570: (100589,), 200571: (100590,), 200573: (100587,), 200574: (100591,), 200575: (100575,), 200576: (100576,), 200578: (100578,), 200580: (100580,), 200581: (100592,), 200582: (100593,), 200583: (100594,), 200584: (100595,), 200588: (100517,), 200592: (100599, 300119, 300120, 100601), 200593: (100600, 300121, 300122, 100602), 200594: (100603,), 200595: (100604,), 200596: (100605,), 200597: (100606,), 200598: (100607,), 200599: (100608,), 200600: (100609,), 200601: (100610,), 200602: (100611,), 200605: (100614,), 200607: (100616,), 200608: (100617,), 200609: (100618,), 200611: (100620,), 200612: (100621,), 200614: (100623, 300123, 300124, 100645), 200615: (100624,), 200616: (100599, 300119, 300120, 100601, 100600, 300121, 300122, 100602), 200619: (100626, 300125, 300126, 100648, 100649), 200620: (100627,), 200622: (100629,), 200623: (100627, 100629), 200626: (100638,), 200627: (100639,), 200628: (100640,), 200630: (100642,), 200631: (100643,), 200632: (100646,), 200633: (100647,), 200634: (100623, 300123, 300124, 100645, 100626, 300125, 300126, 100648, 100649), 210001: (110001,), 210002: (110002,), 210006: (110004,), 210007: (110005,)}
V140_COMMODITY_NAMES = {200001: 'M4A1 [AF]', 200002: 'AK47-R', 200003: 'MP5', 200004: 'Remington MSR', 200005: 'Desert Eagle', 200006: 'AK47 [AF]', 200007: 'Benelli Nova', 200008: 'M249', 200009: 'USP', 200010: 'Frag Grenade', 200011: 'Flashbang', 200012: 'Smoke Bomb', 200019: 'Falcon', 200020: 'SCAR', 200021: 'Bulletproof Helmet', 200022: 'Bulletproof Vest', 200026: 'No.3 Backpack', 200027: 'No.4 Backpack', 200028: 'No.5 Backpack', 200029: 'Dutch', 200031: 'Steyr Aug A1', 200032: 'Borders a badge', 200033: 'Badges border 2', 200034: 'Badges border 3', 200035: 'Badges border 4', 200036: 'Badges border 5', 200037: 'Badges border 6', 200038: 'Badges Borders 7', 200039: 'Badges Borders 8', 200040: 'Badges border 9', 200041: 'Badges border 10', 200042: 'Insignia 1', 200043: 'Insignia 2', 200044: 'Insignia 3', 200045: 'Insignia 4', 200046: 'Insignia 5', 200047: 'Insignia 6', 200048: 'Insignia 7', 200049: 'Insignia 8', 200050: 'Insignia 9', 200051: 'Insignia 10', 200052: 'Background a badge', 200053: 'Badges Background 2', 200054: 'Badges background 3', 200055: 'Badge background 4', 200056: 'Badges background 5', 200057: 'Badges background 6', 200058: 'Badges background 7', 200059: 'Badges background 8', 200060: 'Badges background 9', 200061: 'Badges Background 10', 200062: 'Speakers', 200064: 'Arctic WM', 200065: 'Barett M95', 200066: 'Jungle Bolo', 200067: 'Regular EXP Bonus Card', 200068: 'Advance EXP Bonus Card', 200069: 'Jason', 200070: 'Yuri', 200071: 'HK G3/SG2', 200074: 'RPK', 200075: 'Advance Combat Helmet (Chief)', 200076: 'M44 Gas Mask (Chief)', 200077: 'Portable Belt (Chief)', 200082: 'Electronic Eye (Falcon)', 200083: 'Hunting Belt (Falcon)', 200086: 'Sting Belt (Mac)', 200087: 'MAC', 200088: 'Chief', 200089: 'QBZ-95', 200090: 'Remington 700', 200091: 'Tauras M608', 200092: 'AN-94', 200093: 'M60', 200094: 'FAMAS', 200095: 'SVD', 200096: 'Titanium Blackblade', 200097: 'Mountain Pick', 200098: 'HE Grenade', 200099: 'M134 Minigun', 200100: 'Respiratory Mask (Yuri)', 200101: 'Military sunglasses (Jason)', 200102: 'Night Vision (Yuri)', 200103: 'Diving goggles (Mac)', 200104: 'Wind mirrors (Chief)', 200105: 'Aviator classics (Dutch)', 200106: 'White framed glasses (Dutch)', 200107: 'Black-rimmed glasses (Jason)', 200108: 'Military combat helmet (Yuri)', 200109: 'Federal cap (Yuri)', 200110: 'Red lightening headscarf (Mac)', 200111: 'Guardian cap (Chief)', 200112: 'Vodka belt (Yuri)', 200113: 'Guardian belt (Chief)', 200114: 'Tactical belt (Yuri)', 200115: 'DJ Gadgets (Mac)', 200116: 'Striped cross belt (Dutch)', 200117: 'Bullet belt (Dutch)', 200118: 'AR15', 200119: 'Minimi Machine Gun', 200120: 'Police belt (Jason)', 200121: 'Marching belt (Jason)', 200122: 'Hunters hat (Falcon)', 200123: 'Skull patch (Falcon)', 200124: 'Benelli Super 90', 200128: 'P90', 200129: 'JSS Sub', 200130: 'Dual Uzi', 200131: 'FN FAL', 200132: 'Zhao', 200133: 'Special combat goggles (Zhao)', 200134: 'Dust masks (Zhao)', 200135: 'Spec Ops Helmet (Zhao)', 200136: 'Spec Ops Fighting Cap (Zhao)', 200137: 'Lightweight Belt (Zhao)', 200138: 'Eastern Alliance Belt (Zhao)', 200139: 'XM8', 200140: 'Omar', 200141: 'Sandy washcloth (Omar)', 200142: 'Desert wolf mask (Omar)', 200143: 'Guerilla Headgear (Omar)', 200144: 'Arab headscarf (Omar)', 200145: 'Damascus broadsword (Omar)', 200146: 'Bomber belt (Omar)', 200147: 'SPAS-12', 200148: 'Colt 1873', 200159: 'Grenade Pack', 200161: 'Rifle Magazine', 200162: 'Machine gun Magazine', 200163: 'Sniper Rifle magazine', 200164: 'Submachine gun Magazine', 200165: 'Shotgun Magazine', 200166: 'Pistol Magazine', 200169: 'Angel', 200172: 'Shark pattern', 200173: 'Grenade Pattern', 200174: 'Handprint', 200175: 'Dagger Pattern', 200176: 'Headshot Pattern', 200177: 'Star Pattern', 200178: 'Demon Pattern', 200179: 'Bullets Pattern', 200180: 'Gear Pattern', 200181: 'Sickle Pattern', 200182: 'Wings Pattern', 200183: 'Snake Pattern', 200184: 'Poison Pattern', 200185: 'Radiation Pattern', 200186: 'War Pattern', 200187: 'F2000', 200188: 'AK74U', 200190: 'M4A1-S', 200191: 'M4A1-H', 200192: 'M4A1-P', 200193: 'AWM-S', 200194: 'AWM-T', 200195: 'Glock 17', 200196: 'Boxing Gloves', 200197: 'Rename Card', 200198: 'K/D Record Clear Card', 200199: 'Special Ray package', 200200: 'Rinvay', 200201: 'Winlose clear card', 200202: 'C4 Defuse Kit', 200203: 'SIG SG 551', 200204: 'Sato', 200205: 'Lightning Helmet (Sato)', 200206: 'Rider Wind Mirrors (Sato)', 200207: 'Champion Mask (Sato)', 200208: 'Driver Tool Pockets (Sato)', 200210: 'Extended Skills grid', 200211: 'FAMAS-R', 200212: 'Desert Eagle-A', 200213: 'Sapper Shovel', 200215: 'Big kill magazine', 200217: 'AR15-A', 200218: 'CT Zaytsev-1', 200219: 'Resurrection currency', 200220: 'Holiday grenades', 200221: 'Insignia 11', 200222: 'Insignia 12', 200223: 'Insignia 13', 200224: 'Insignia 14', 200225: 'Insignia 15', 200226: 'Insignia 16', 200227: 'Insignia 17', 200228: 'Insignia 18', 200229: 'Insignia 19', 200230: 'Insignia 20', 200231: 'AR15-FELN', 200232: 'Ramirez', 200233: 'Hawkins', 200234: 'M4A1-M', 200235: 'Ak47-T', 200236: 'Beretta 92', 200237: 'Dragon Belt (Rinvay)', 200238: 'GSDU Headset (Jason)', 200244: 'India glasses (Rinvay)', 200246: 'QJY-88', 200247: 'Jackhammer M3-A2', 200248: 'Army Hand Axe', 200249: 'Alien lure Ray', 200250: 'Jetpack', 200251: 'Super Storm Mech license I', 200252: 'Super Storm Mech license II', 200253: 'Super behemoth mech license', 200254: 'Supply tank shells', 200255: 'Tank armor', 200263: 'Fool grenade', 200264: 'QBU-88', 200265: 'UMP45', 200266: 'AK47-B', 200267: 'SWM629SH', 200268: 'Pale Lightning Helmet', 200269: 'Dragon Headband (Rinvay)', 200270: 'Dragon Glasses (Rinvay)', 200271: 'Beastmaster Headscarf', 200272: 'Spotted scarf (Hawkins)', 200273: 'Perak Pockets (Ramirez)', 200274: 'Alpha', 200275: 'Perak', 200276: 'Gerbils wind mirror', 200279: 'Alpha wind mirror', 200280: 'Alpha Combat Helmet', 200281: 'International Police Belt', 200282: 'Lurking masks', 200283: 'Latent mask (Ramirez)', 200287: 'RPK-S', 200288: '????MINIGUN', 200291: 'SCAR-S', 200293: 'Labor shovel', 200295: 'AK47', 200296: 'M4A1', 200297: 'AWM', 200298: 'AWM-A', 200302: '92 pistol', 200303: 'OTs-14', 200304: 'M240LW', 200305: 'AK47-A', 200310: 'Female fighting belt', 200311: 'Gucci glasses', 200312: 'Paladin cap', 200314: 'Mutation grenade', 200316: 'KACSAW', 200317: 'Variation of the virus', 200318: 'Variation magazine', 200319: 'Candy Bomb', 200320: 'Standard headphone battle', 200321: 'Red Devils battle headphones', 200322: 'Gold Medal Arctic WM-S', 200323: 'Silver Medal Arctic WM-S', 200324: 'Bronze Medal Arctic WM-S', 200325: 'Gold Medal M4A1-S', 200326: 'Silver Medal M4A1-S', 200327: 'Bronze Medal M4A1-S', 200328: 'Target Pattern', 200329: 'Wolf spy', 200330: 'Impartial', 200331: 'M4A1-A', 200332: 'AR15-S', 200336: 'OPS bulletproof helmet', 200342: 'Championship belt', 200343: 'TAR21', 200344: 'A-Point Pattern', 200345: 'B-Point Pattern', 200346: 'Mech Pattern', 200347: 'Inverse War Pattern', 200348: 'Cowboy Pattern', 200349: 'Cyborg Pattern', 200350: 'Biochemical Pattern', 200351: 'Space pattern', 200352: 'Clown pattern', 200353: 'Temptation Pattern', 200356: 'DSR-1', 200357: 'MAUL', 200360: 'Scorpion swords', 200361: 'Air filter', 200363: 'Riot police belt', 200364: 'Anti-viral respiratory masks', 200368: 'Red Action helmet', 200371: 'AK47-K', 200372: 'M4A1-H', 200373: 'Bella', 200375: 'Kevin', 200378: 'Nepal saber', 200380: '03 rifle', 200388: 'Gear painting', 200389: 'Covers painting', 200390: 'Skull painting', 200397: 'Painting lure Ray', 200399: 'Destruction painting', 200414: 'Alpha Operations pockets', 200417: 'Reds pennant belt', 200421: 'SEAL combat washcloth', 200426: 'Camo XM8', 200439: 'Outdoor canvas pockets', 200440: 'Players shot glasses', 200441: 'sound canceling headphones', 200444: 'SEAL Tactical Belt', 200446: 'Ultimax100', 200447: 'Phantom', 200448: 'Pumpkin Grenade', 200457: 'Jasmine', 200459: '????95??', 200460: 'Firecracker grenade', 200465: 'Camo  AK74U', 200466: 'AR15- Black Mamba', 200467: 'SCAR- gold Viper', 200468: 'M95- Cobra', 200469: 'Gatlin - mad python', 200470: 'Snake Desert', 200471: 'King of the jungle - snake', 200481: 'FMG dual wield', 200482: '09 style shotgun', 200483: 'snake Series Set', 200484: 'snake Series Set', 200485: 'Special 95-style', 200486: '10 sniper', 200489: 'Encryption key box arms', 200490: '??????MSR', 200491: 'DSR-1', 200492: 'M4A1-S', 200493: 'SCAR-S', 200494: 'M4A1-H', 200495: 'F2000', 200496: 'OTs-14', 200497: 'FAMAS-R', 200498: 'Uzi??????????', 200499: '??????????', 200500: 'Beretta92', 200501: 'MAUL', 200505: 'Camo  FAL', 200506: 'M4A1-H', 200507: 'F2000', 200508: 'M4A1-S', 200509: 'DSR-1', 200512: 'Tank Kit', 200513: 'Battle Set', 200514: 'Mech Suit', 200515: 'Mutation set', 200516: 'Black fighting belt', 200517: 'Black fighting headphones', 200518: 'Black fighting glasses', 200519: 'Variability of serum', 200520: 'Gene enhancer', 200521: 'Enhanced virus', 200522: 'Variety Set', 200523: 'April FoolSet', 200524: 'Camo  KACSAW', 200526: 'AUGA3', 200527: 'A super mech license', 200537: 'HKG11', 200539: 'Leather fashion cap', 200540: 'Dark visor mirror', 200541: 'Jungle survival knife', 200549: 'Cutting-edge suite', 200550: 'Three bursts suit', 200552: 'Blood crossbow', 200553: 'HK416', 200554: 'AK12', 200555: 'TPG1', 200556: 'Bloodthirsty Rose', 200557: 'Sniper suit', 200558: 'Gun suit', 200559: '????????', 200560: 'FN57', 200562: '500AP discount coupons', 200563: '300AP discount coupons', 200566: 'Children painting (2)', 200567: 'Thunder 999', 200569: 'Blood colored headscarf', 200570: 'Middle East Plaid Scarf', 200571: 'Wild boy standard belt', 200573: 'Evil Chaozong', 200574: 'Tower defense expert card', 200575: 'Turned hero', 200576: 'Straightforward shooting', 200578: 'Pilfering', 200580: 'Bloody Harvest', 200581: 'A tank license', 200582: 'Dual wield ACP', 200583: 'ARX160', 200584: 'Knuckles', 200588: 'Powerful physique', 200592: 'Angela', 200593: 'Sofia', 200594: 'SCAR Megalodon', 200595: 'Flames fighting spirit', 200596: 'DE shark', 200597: 'Mood headdress', 200598: 'brown sunglasses', 200599: 'Fashion fight purse', 200600: 'American cap', 200601: 'Rimless sunglasses gray', 200602: 'American Police pockets', 200605: 'Camo  Brothers', 200607: 'Bullet Time', 200608: 'LSAT', 200609: 'Polar ice flame', 200611: 'L85', 200612: 'MP5SD10', 200614: 'Zhang Jie - Police Pioneer', 200615: 'Hurricane Hammer', 200616: 'Sofia & Angela', 200619: 'Zhang Jie - King City', 200620: 'Super Compound Bow', 200622: 'Explosion arrow', 200623: 'Compound Bow Package', 200626: 'Barrett M107', 200627: 'MINI14', 200628: 'ACE32', 200630: 'M1911', 200631: 'Bat', 200632: 'Nether Duwang', 200633: 'Huang Jin Zunlong Nepal', 200634: 'Zhang Jie - double camp', 210001: 'AK74U-KOS', 210002: 'AR15-KOS', 210006: 'The Razorback', 210007: 'Boar Hooves'}

V140_ROLE_ITEM_IDS = frozenset(
    item_id for item_id, loc in V140_ITEM_DEFAULT_LOCATIONS.items()
    if int(loc) in (0x0A, 0x0B)
)

V140_STARTER_GIDS = (
    V109_ROLE_GID,
    V109_BAG1_GID,
    V109_BAG2_GID,
    V109_PRIMARY_GID,
    V127_PISTOL_GID,
    V127_MELEE_GID,
    V127_GRENADE_GID,
    V129_SOFIA_HAND_GID,
    V129_SOFIA_UPPER_GID,
    V129_SOFIA_HAIR_GID,
    R20_STRENGTH_GID,
)

# Immutable-by-convention template used to seed each SQLite player profile.
# V111_INVENTORY becomes a per-player proxy later in this section.
V140_STARTER_INVENTORY = [dict(p) for p in V111_INVENTORY]


def _v140_sanitize_prop(raw):
    if not isinstance(raw, dict):
        return None
    try:
        gid = int(raw.get("gid", 0)) & 0xFFFFFFFFFFFFFFFF
        item_id = int(raw.get("item_id", 0)) & 0xFFFFFFFF
        if gid == 0 or item_id == 0:
            return None
        return {
            "gid": gid,
            "item_id": item_id,
            "owner_gid": int(raw.get("owner_gid", 0)) & 0xFFFFFFFFFFFFFFFF,
            "location": int(raw.get("location", V109_LOC_BAG)) & 0xFF,
            "durability": max(0, int(raw.get("durability", 100))),
            "durability_max": max(0, int(raw.get("durability_max", 100))),
            # Preserve the catalog's -1/0 permanent-item sentinels.
            "avail_hours": int(raw.get("avail_hours", V140_ITEM_AVAIL_HOURS)),
            "validity": int(raw.get("validity", raw.get("avail_hours", V140_ITEM_AVAIL_HOURS))),
            "gain_type": max(0, int(raw.get("gain_type", 1))) & 0xFF,
            # Legacy rows have no purchase time and stay non-expiring.
            "obtained_at": max(0, int(raw.get("obtained_at", 0) or 0)),
            "expires_at": max(0, int(raw.get("expires_at", 0) or 0)),
        }
    except Exception:
        return None


def _v140_default_state():
    inv = []
    for p in V140_STARTER_INVENTORY:
        q = _v140_sanitize_prop(p)
        if q:
            inv.append(q)

    max_gid = max((int(p["gid"]) for p in inv), default=((V109_UIN & 0xffffffff) << 32))
    return {
        "version": 1,
        "experience": 0,
        "wallet": {
            "ap": V140_DEFAULT_AP,
            "gp": V140_DEFAULT_GP,
            "mp": V140_DEFAULT_MP,
        },
        "current_role_gid": V109_ROLE_GID,
        "current_bag_gid": V109_BAG1_GID,
        "next_gid": (max_gid + 1) & 0xFFFFFFFFFFFFFFFF,
        "inventory": inv,
    }


def _v140_load_legacy_state():
    """Read/sanitize the old JSON only for one-time SQLite migration."""
    if not V140_MALL_STATE_PATH.exists():
        return None
    state = _v140_default_state()

    try:
        raw = json.loads(V140_MALL_STATE_PATH.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("top-level mall state must be an object")

        loaded = []
        used = set()
        for p in raw.get("inventory", []):
            q = _v140_sanitize_prop(p)
            if q and q["gid"] not in used:
                used.add(q["gid"])
                loaded.append(q)

        # Never let a damaged test-state file remove the proven starter roots.
        defaults = {int(p["gid"]): _v140_sanitize_prop(p) for p in V140_STARTER_INVENTORY}
        for gid in V140_STARTER_GIDS:
            if gid not in used and defaults.get(gid):
                loaded.append(defaults[gid])
                used.add(gid)

        if loaded:
            state["inventory"] = loaded

        wallet = raw.get("wallet") if isinstance(raw.get("wallet"), dict) else {}
        state["wallet"] = {
            "ap": max(0, int(wallet.get("ap", V140_DEFAULT_AP))),
            "gp": max(0, int(wallet.get("gp", V140_DEFAULT_GP))),
            "mp": max(0, int(wallet.get("mp", V140_DEFAULT_MP))),
        }
        try:
            state["experience"] = max(
                0, min(int(raw.get("experience", 0)), 0x7FFFFFFF)
            )
        except (TypeError, ValueError):
            state["experience"] = 0

        role_gid = int(raw.get("current_role_gid", V109_ROLE_GID)) & 0xFFFFFFFFFFFFFFFF
        if not any(int(p["gid"]) == role_gid for p in state["inventory"]):
            role_gid = V109_ROLE_GID
        state["current_role_gid"] = role_gid
        state["current_bag_gid"] = (
            int(raw.get("current_bag_gid", V109_BAG1_GID))
            & 0xFFFFFFFFFFFFFFFF
        )

        max_gid = max((int(p["gid"]) for p in state["inventory"]), default=0)
        next_gid = int(raw.get("next_gid", max_gid + 1)) & 0xFFFFFFFFFFFFFFFF
        if next_gid == 0 or next_gid <= max_gid:
            next_gid = (max_gid + 1) & 0xFFFFFFFFFFFFFFFF
        state["next_gid"] = next_gid

        return state
    except Exception as e:
        print(f"[MALL-SQLITE-v4] legacy JSON import skipped: {e}", flush=True)
        return None


class _V140PlayerStateManager:
    """Per-thread/per-UIN in-memory working sets backed by SQLite transactions."""

    def __init__(self, db):
        self.db = db
        self._tls = threading.local()
        self._lock = threading.RLock()
        self._cache = {}
        self._last_active_uin = None

    def current_uin(self):
        # Runtime packet threads explicitly select their authenticated UIN.
        # 10001 is a compatibility fallback for legacy helper/self-test code.
        return int(getattr(self._tls, "uin", 10001))

    def select(self, uin):
        uin = int(uin)
        self._tls.uin = uin
        self._last_active_uin = uin
        self.ensure(uin)
        return uin

    def wallet_for_local_sync(self):
        uin = self._last_active_uin
        if uin is None:
            return dict(_v140_default_state()["wallet"])
        return self.ensure(int(uin))["wallet"]

    def ensure(self, uin):
        uin = int(uin)
        with self._lock:
            cached = self._cache.get(uin)
            if cached is not None:
                return cached

            legacy_state = _v140_load_legacy_state()
            state, created, imported = self.db.ensure_player_state(
                uin,
                _v140_default_state(),
                legacy_state=legacy_state,
                legacy_source=str(V140_MALL_STATE_PATH),
            )
            self._cache[uin] = state
            if created:
                log(
                    "MALL-SQLITE",
                    f"v4 player state created uin={uin} "
                    f"legacy_imported={imported} inventory={len(state['inventory'])} "
                    f"AP={state['wallet']['ap']} GP={state['wallet']['gp']} "
                    f"MP={state['wallet']['mp']}",
                )
            return state

    def state(self):
        return self.ensure(self.current_uin())

    def save(self, reason="update", moneyflow_rows=None):
        uin = self.current_uin()
        state = self.state()
        self.db.save_player_state(
            uin,
            state,
            reason=reason,
            moneyflow_rows=moneyflow_rows,
        )
        return uin

    def reload(self, uin=None):
        uin = self.current_uin() if uin is None else int(uin)
        with self._lock:
            self._cache[uin] = self.db.load_player_state(uin)
            return self._cache[uin]


class _V140StateProxy(MutableMapping):
    def __init__(self, manager):
        self._manager = manager

    def _d(self):
        return self._manager.state()

    def __getitem__(self, key):
        return self._d()[key]

    def __setitem__(self, key, value):
        self._d()[key] = value

    def __delitem__(self, key):
        del self._d()[key]

    def __iter__(self):
        return iter(self._d())

    def __len__(self):
        return len(self._d())


class _V140InventoryProxy(MutableSequence):
    def __init__(self, manager):
        self._manager = manager

    def _l(self):
        return self._manager.state()["inventory"]

    def __getitem__(self, index):
        return self._l()[index]

    def __setitem__(self, index, value):
        self._l()[index] = value

    def __delitem__(self, index):
        del self._l()[index]

    def __len__(self):
        return len(self._l())

    def insert(self, index, value):
        self._l().insert(index, value)


_V140_PLAYER_STATE = _V140PlayerStateManager(PLAYER_DB)
V140_MALL_STATE = _V140StateProxy(_V140_PLAYER_STATE)
V111_INVENTORY = _V140InventoryProxy(_V140_PLAYER_STATE)


def _v140_current_role_gid():
    gid = int(V140_MALL_STATE.get("current_role_gid", V109_ROLE_GID))
    if any(int(p.get("gid", 0)) == gid for p in V111_INVENTORY):
        return gid
    return V109_ROLE_GID


def _v140_wallet():
    w = V140_MALL_STATE.setdefault(
        "wallet",
        {"ap": V140_DEFAULT_AP, "gp": V140_DEFAULT_GP, "mp": V140_DEFAULT_MP},
    )
    return w


def _v140_save_state(reason="update", moneyflow_rows=None):
    V140_MALL_STATE["version"] = 1
    V140_MALL_STATE["inventory"] = [dict(p) for p in V111_INVENTORY]
    V140_MALL_STATE["current_role_gid"] = int(_v140_current_role_gid())
    V140_MALL_STATE["current_bag_gid"] = int(_v141_current_bag_gid())

    max_gid = max((int(p.get("gid", 0)) for p in V111_INVENTORY), default=0)
    nxt = int(V140_MALL_STATE.get("next_gid", max_gid + 1)) & 0xFFFFFFFFFFFFFFFF
    if nxt == 0 or nxt <= max_gid:
        nxt = (max_gid + 1) & 0xFFFFFFFFFFFFFFFF
    V140_MALL_STATE["next_gid"] = nxt

    uin = _V140_PLAYER_STATE.save(
        reason,
        moneyflow_rows=moneyflow_rows,
    )
    log(
        "MALL-SQLITE",
        f"v5 state committed transactionally reason={reason} uin={uin} "
        f"moneyflow={len(moneyflow_rows or ())} "
        f"inventory={len(V111_INVENTORY)} "
        f"role=0x{_v140_current_role_gid():016x} "
        f"bag=0x{_v141_current_bag_gid():016x} "
        f"AP={_v140_wallet()['ap']} GP={_v140_wallet()['gp']} MP={_v140_wallet()['mp']}",
    )


def _v140_find_prop(gid):
    gid = int(gid) & 0xFFFFFFFFFFFFFFFF
    return next((p for p in V111_INVENTORY if int(p.get("gid", 0)) == gid), None)


def _v140_is_role_item(item_id):
    return int(item_id) in V140_ROLE_ITEM_IDS


def _v140_role_slot(item_id):
    loc = int(V140_ITEM_DEFAULT_LOCATIONS.get(int(item_id), -1))
    return loc if loc in (0x0A, 0x0B) else None


# PH 1.0.0.24 RawItemDatas: MainShowType=1, Location=0/1/2/7.
# These sockets belong to a character; the same numbers in a backpack refer
# to weapons. Do not infer accessory ownership from a socket number alone.
V173_CHARACTER_ACCESSORY_SLOTS = {
    100017: 0,
    100018: 1,
    100019: 2,
    100023: 0,
    100024: 1,
    100025: 2,
    100029: 0,
    100030: 1,
    100031: 2,
    100042: 7,
    100081: 1,
    100082: 1,
    100083: 1,
    100084: 1,
    100085: 1,
    100086: 1,
    100087: 1,
    100088: 1,
    100089: 0,
    100090: 0,
    100091: 0,
    100092: 0,
    100093: 2,
    100094: 2,
    100095: 2,
    100096: 2,
    100097: 2,
    100098: 2,
    100101: 2,
    100102: 2,
    100103: 0,
    100104: 1,
    100116: 1,
    100117: 1,
    100118: 0,
    100119: 0,
    100120: 2,
    100121: 2,
    100124: 1,
    100125: 1,
    100126: 0,
    100127: 0,
    100128: 2,
    100129: 2,
    100130: 0,
    100131: 0,
    100200: 0,
    100201: 1,
    100202: 1,
    100203: 2,
    100218: 1,
    100219: 1,
    100223: 2,
    100224: 0,
    100226: 0,
    100230: 1,
    100264: 0,
    100265: 0,
    100266: 1,
    100267: 0,
    100268: 1,
    100269: 2,
    100272: 1,
    100273: 0,
    100275: 1,
    100276: 0,
    100277: 2,
    100278: 1,
    100279: 0,
    100303: 2,
    100304: 1,
    100305: 0,
    100320: 0,
    100321: 0,
    100322: 0,
    100323: 0,
    100324: 0,
    100325: 0,
    100335: 0,
    100341: 0,
    100369: 2,
    100370: 1,
    100371: 0,
    100372: 2,
    100373: 1,
    100377: 0,
    100387: 0,
    100389: 0,
    100425: 2,
    100428: 2,
    100432: 1,
    100450: 2,
    100451: 1,
    100452: 0,
    100455: 2,
    100460: 0,
    100490: 0,
    100527: 2,
    100528: 0,
    100529: 1,
    100530: 2,
    100549: 0,
    100550: 1,
    100551: 2,
    100562: 0,
    100588: 0,
    100589: 1,
    100590: 2,
    100601: 0,
    100602: 0,
    100606: 0,
    100607: 1,
    100608: 2,
    100609: 0,
    100610: 1,
    100611: 2,
    100645: 0,
    100648: 0,
    100649: 1,
}


def _v173_character_accessory_slot(item_id):
    return V173_CHARACTER_ACCESSORY_SLOTS.get(int(item_id))


def _v173_character_bundle_component_roles():
    """Map bundled character appearance parts to the role roots they belong to."""
    component_roles = {}
    for bundle in V140_COMMODITY_BUNDLES.values():
        items = tuple(int(item_id) for item_id in bundle)
        if sum(300000 <= item_id < 400000 for item_id in items) < 2:
            continue
        role_item_id = None
        for item_id in items:
            if _v140_role_slot(item_id) is not None:
                role_item_id = item_id
                continue
            if (role_item_id is not None
                    and _v173_character_accessory_slot(item_id) is not None):
                component_roles.setdefault(item_id, set()).add(role_item_id)
    return {
        item_id: frozenset(role_item_ids)
        for item_id, role_item_ids in component_roles.items()
    }


V173_CHARACTER_BUNDLE_COMPONENT_ROLE_ITEMS = (
    _v173_character_bundle_component_roles()
)


def _v173_is_character_bundle_component(prop):
    item_id = int(prop.get("item_id", 0))
    return (
        item_id in V173_CHARACTER_BUNDLE_COMPONENT_ROLE_ITEMS
        and int(prop.get("durability_max", prop.get("durability", 0))) == 0
    )


def _v173_repair_accessory_owners():
    """Restore bundled character parts and return misplaced accessories to storage."""
    invalid_owners = _v141_bag_gids() | {V110_BAG_MOUNT_OWNER}
    by_gid = {int(prop["gid"]): prop for prop in V111_INVENTORY}
    changes = []
    for prop in V111_INVENTORY:
        item_id = int(prop.get("item_id", 0))
        owner_gid = int(prop.get("owner_gid", 0))
        role_item_ids = V173_CHARACTER_BUNDLE_COMPONENT_ROLE_ITEMS.get(item_id)
        if role_item_ids and _v173_is_character_bundle_component(prop):
            current_owner = by_gid.get(owner_gid)
            if (
                current_owner is not None
                and int(current_owner.get("item_id", 0)) in role_item_ids
                and _v140_role_slot(int(current_owner.get("item_id", 0))) is not None
            ):
                continue

            role_roots = [
                candidate for candidate in V111_INVENTORY
                if int(candidate.get("item_id", 0)) in role_item_ids
                and _v140_role_slot(int(candidate.get("item_id", 0))) is not None
            ]
            if role_roots:
                selected_role_gid = int(_v140_current_role_gid())
                target = next(
                    (candidate for candidate in role_roots
                     if int(candidate["gid"]) == owner_gid),
                    None,
                ) or next(
                    (candidate for candidate in role_roots
                     if int(candidate["gid"]) == selected_role_gid),
                    role_roots[0],
                )
                default_loc = int(V140_ITEM_DEFAULT_LOCATIONS.get(item_id, -1))
                location = 0xFF if default_loc < 0 else default_loc
                before = (owner_gid, int(prop["location"]))
                prop["owner_gid"], prop["location"] = int(target["gid"]), location
                changes.append((
                    int(prop["gid"]), item_id, before,
                    (int(target["gid"]), location),
                ))
            elif owner_gid in invalid_owners:
                before = (owner_gid, int(prop["location"]))
                prop["owner_gid"], prop["location"] = 0, V109_LOC_BAG
                changes.append((
                    int(prop["gid"]), item_id, before, (0, V109_LOC_BAG),
                ))
            continue

        if (_v173_character_accessory_slot(item_id) is not None
                and owner_gid in invalid_owners):
            before = (owner_gid, int(prop["location"]))
            prop["owner_gid"], prop["location"] = 0, V109_LOC_BAG
            changes.append((int(prop["gid"]), item_id, before, (0, V109_LOC_BAG)))
    return changes


def _v173_apply_accessory_equip(op):
    if int(op.get("operation", -1)) != PROP_OP_EQUIP:
        return None
    subject = _v140_find_prop(int(op.get("subject_gid", 0)))
    if subject is None:
        return None
    item_id = int(subject.get("item_id", 0))
    slot = _v173_character_accessory_slot(item_id)
    if slot is None:
        return None

    effective = dict(op)
    roles = {
        int(prop["gid"]): prop for prop in V111_INVENTORY
        if _v140_role_slot(int(prop.get("item_id", 0))) is not None
    }
    requested = int(op.get("target_gid", 0))
    owner = requested if requested in roles else int(_v140_current_role_gid())
    if owner not in roles:
        effective.update(target_gid=int(subject.get("owner_gid", 0)),
                         location=int(subject.get("location", V109_LOC_BAG)))
        return "v173 accessory equip ignored: no owned character root", effective

    # Accessories share sockets with bundled role appearance parts. Keep
    # those parts mounted; only standalone accessories replace one another.
    for other in V111_INVENTORY:
        if (other is subject or int(other.get("owner_gid", 0)) != owner
                or int(other.get("location", V109_LOC_BAG)) != slot):
            continue
        if (_v173_is_character_bundle_component(subject)
                or _v173_is_character_bundle_component(other)):
            continue
        other["owner_gid"], other["location"] = 0, V109_LOC_BAG
    subject["owner_gid"], subject["location"] = owner, slot
    effective.update(target_gid=owner, location=slot)
    return (f"v173 accessory equip item={item_id} character=0x{owner:016x} "
            f"slot=0x{slot:02x}"), effective


# v141 current-bag invariant:
# TGAvatarChar_Data.GetCharInfo derives one scalar DefaultBagIndex by testing
# every bag with IsEquipedToRoot(OwnerPropId). Therefore exactly ONE normal
# backpack may be mounted to root (literal owner 1) at a time.
# Bag 1 and Bag 2 are starter/entitlement props. Discover purchasable bags from
# the Mall catalog so Bags 3–5 and future catalog entries use the same rules.
V141_STARTER_BAG_ITEM_IDS = frozenset((
    V109_BAG1_ITEM_ID,
    V109_BAG2_ITEM_ID,
))


def _v141_catalog_bag_item_ids():
    bag_item_ids = set()
    for commodity_id, bundle_item_ids in V140_COMMODITY_BUNDLES.items():
        commodity_name = str(
            V140_COMMODITY_NAMES.get(int(commodity_id), "")
        ).casefold()
        if not re.search(r"\b(?:backpack|bag)\b", commodity_name):
            continue

        bundle_item_ids = [int(item_id) for item_id in bundle_item_ids]
        # Prefer bundle items whose catalog default location is the Bag root.
        # If a future backpack entry omits that metadata, its first bundled
        # item is the purchased root, matching this catalog's bundle ordering.
        root_items = [
            item_id for item_id in bundle_item_ids
            if int(V140_ITEM_DEFAULT_LOCATIONS.get(item_id, -1))
            == V109_LOC_BAG
        ]
        if not root_items and bundle_item_ids:
            root_items = [bundle_item_ids[0]]
        bag_item_ids.update(
            item_id for item_id in root_items
            if _v173_character_accessory_slot(item_id) is None
        )

    return frozenset(bag_item_ids)


V141_BAG_ITEM_IDS = (
    V141_STARTER_BAG_ITEM_IDS | _v141_catalog_bag_item_ids()
)


def _v141_is_bag_item(item_id):
    return int(item_id) in V141_BAG_ITEM_IDS


def _v141_bag_gids():
    return {int(prop["gid"]) for prop in _v141_bag_props()}


def _v141_bag_props():
    return [
        p for p in V111_INVENTORY
        if _v141_is_bag_item(p.get("item_id", 0))
    ]


def _v141_current_bag_gid():
    bags = _v141_bag_props()
    valid = {int(p["gid"]) for p in bags}

    persisted = (
        int(V140_MALL_STATE.get("current_bag_gid", 0))
        & 0xFFFFFFFFFFFFFFFF
    )
    if persisted in valid:
        return persisted

    mounted = [
        int(p["gid"]) for p in bags
        if int(p.get("owner_gid", 0)) == V110_BAG_MOUNT_OWNER
    ]
    if len(mounted) == 1:
        return mounted[0]

    if V109_BAG1_GID in valid:
        return V109_BAG1_GID
    return min(valid) if valid else V109_BAG1_GID


def _v141_set_current_bag(preferred_gid=None, reason="bag-select"):
    bags = _v141_bag_props()
    valid = {int(p["gid"]) for p in bags}

    preferred = (
        (int(preferred_gid) & 0xFFFFFFFFFFFFFFFF)
        if preferred_gid is not None
        else _v141_current_bag_gid()
    )
    if preferred not in valid:
        preferred = (
            V109_BAG1_GID
            if V109_BAG1_GID in valid
            else (min(valid) if valid else 0)
        )

    changes = []
    for p in bags:
        gid = int(p["gid"])
        before = (
            int(p.get("owner_gid", 0)),
            int(p.get("location", V109_LOC_BAG)),
        )
        after = (
            V110_BAG_MOUNT_OWNER if gid == preferred else 0,
            V109_LOC_BAG,
        )

        p["owner_gid"], p["location"] = after

        if before != after:
            changes.append((gid, before, after))

    if preferred:
        V140_MALL_STATE["current_bag_gid"] = preferred

    # Keep persistent object coherent immediately; disk write happens through
    # the normal _v140_save_state transaction.
    V140_MALL_STATE["inventory"] = [dict(p) for p in V111_INVENTORY]

    return preferred, changes


def _v141_bag_invariant_text():
    return " ; ".join(
        (
            f"gid=0x{int(p['gid']):016x}"
            f"/item={int(p['item_id'])}"
            f"/owner=0x{int(p.get('owner_gid',0)):016x}"
            f"/loc=0x{int(p.get('location',V109_LOC_BAG)):02x}"
        )
        for p in _v141_bag_props()
    )


# SQLite v4: repair each authenticated player's bag invariant after that
# player's state has been selected. Do not mutate an arbitrary profile at import.
def _v140_prop_is_expired(prop, now=None):
    """Return whether a Mall prop's persisted expiry time has passed."""
    now = int(time.time() if now is None else now)
    try:
        expires_at = int(prop.get("expires_at", 0) or 0)
    except (AttributeError, TypeError, ValueError):
        return False
    return expires_at > 0 and expires_at <= now


def _v140_expire_due_items(now=None, reason="item-expiration"):
    """Expire Mall props without deleting equipment stored inside backpacks."""
    now = int(time.time() if now is None else now)
    inventory = list(V111_INVENTORY)
    expired_gids = {
        int(prop.get("gid", 0))
        for prop in inventory
        if _v140_prop_is_expired(prop, now=now)
        and int(prop.get("gid", 0)) != 0
    }
    if not expired_gids:
        return []

    expired_props = [
        prop for prop in inventory
        if int(prop.get("gid", 0)) in expired_gids
    ]

    # v159: owner_gid is both bundle ownership and equipment placement.
    # Detach valid contents before removing an expired backpack.
    expired_bag_gids = {
        int(prop.get("gid", 0))
        for prop in expired_props
        if _v141_is_bag_item(int(prop.get("item_id", 0)))
    }
    detached_from_bags = []
    if expired_bag_gids:
        for prop in inventory:
            gid = int(prop.get("gid", 0))
            owner_gid = int(prop.get("owner_gid", 0))
            if gid == 0 or gid in expired_gids:
                continue
            if owner_gid not in expired_bag_gids:
                continue
            old_loc = int(prop.get("location", V109_LOC_BAG))
            prop["owner_gid"] = 0
            prop["location"] = V109_LOC_BAG
            detached_from_bags.append((gid, owner_gid, old_loc))

    removed_gids = set(expired_gids)
    while True:
        owned_gids = {
            int(prop.get("gid", 0))
            for prop in inventory
            if int(prop.get("owner_gid", 0)) in removed_gids
            and int(prop.get("gid", 0)) != 0
        }
        expanded = removed_gids | owned_gids
        if expanded == removed_gids:
            break
        removed_gids = expanded

    removed_props = [
        prop for prop in inventory
        if int(prop.get("gid", 0)) in removed_gids
    ]

    current_role_gid = int(
        V140_MALL_STATE.get("current_role_gid", V109_ROLE_GID)
    )
    if current_role_gid in removed_gids:
        V140_MALL_STATE["current_role_gid"] = V109_ROLE_GID

    V111_INVENTORY[:] = [
        prop for prop in inventory
        if int(prop.get("gid", 0)) not in removed_gids
    ]

    preferred_bag = V140_MALL_STATE.get("current_bag_gid")
    selected_bag, bag_changes = _v141_set_current_bag(
        preferred_bag,
        reason=reason,
    )
    _v140_save_state(reason)

    expired_text = ",".join(
        "0x%016x" % gid for gid in sorted(expired_gids)
    )
    log(
        "MALL-EXPIRY",
        f"v159 expired={len(expired_props)} removed={len(removed_props)} "
        f"owned_removed={len(removed_props) - len(expired_props)} "
        f"bag_contents_detached={len(detached_from_bags)} "
        f"current_bag=0x{int(selected_bag):016x} "
        f"bag_changes={len(bag_changes)} "
        f"now={now} gids=[{expired_text}]",
    )
    if detached_from_bags:
        log(
            "MALL-BAG",
            "v159 expired backpack preserved contents: "
            + " | ".join(
                f"gid=0x{gid:016x} from_bag=0x{bag_gid:016x} "
                f"old_loc=0x{old_loc:02x} -> owner=0 loc=0x{V109_LOC_BAG:02x}"
                for gid, bag_gid, old_loc in detached_from_bags
            ),
        )
    return removed_props


def _v170_reconcile_progression_skills():
    """Synchronize normal PVE skill ownership to persisted Experience.

    Normal UnlockWay_1==1 skills are authoritative progression rewards:
      * earned rows are present;
      * unearned rows are absent.

    Rank-127/event-condition skills are outside V170_PVE_LEVEL_SKILL_IDS and
    are therefore completely untouched.
    """
    experience = max(0, int(V140_MALL_STATE.get("experience", 0)))

    eligible_rows = [
        (int(item_id), int(required_level), int(min_exp), str(name))
        for item_id, required_level, min_exp, name in V170_PVE_LEVEL_SKILLS
        if experience >= int(min_exp)
    ]
    eligible_ids = {row[0] for row in eligible_rows}

    revoked = []
    kept_inventory = []
    for prop in list(V111_INVENTORY):
        item_id = int(prop.get("item_id", 0))
        if (
            item_id in V170_PVE_LEVEL_SKILL_IDS
            and item_id not in eligible_ids
        ):
            meta = next(
                (
                    row for row in V170_PVE_LEVEL_SKILLS
                    if int(row[0]) == item_id
                ),
                None,
            )
            if meta is not None:
                revoked.append(
                    (
                        int(prop.get("gid", 0)),
                        item_id,
                        int(meta[1]),
                        int(meta[2]),
                        str(meta[3]),
                    )
                )
            continue
        kept_inventory.append(prop)

    if revoked:
        V111_INVENTORY[:] = kept_inventory

    owned_item_ids = {
        int(prop.get("item_id", 0)) for prop in V111_INVENTORY
    }
    missing = [
        row for row in eligible_rows if row[0] not in owned_item_ids
    ]

    used_gids = {int(prop.get("gid", 0)) for prop in V111_INVENTORY}
    granted = []
    for item_id, required_level, min_exp, name in missing:
        gid = _v140_next_gid(used_gids)
        used_gids.add(gid)
        V111_INVENTORY.append(
            {
                "gid": gid,
                "item_id": item_id,
                "owner_gid": 0,
                "location": V109_LOC_BAG,
                "durability": 0,
                "durability_max": 0,
                "avail_hours": V140_ITEM_AVAIL_HOURS,
                "validity": V140_ITEM_AVAIL_HOURS,
                "gain_type": 1,
                "obtained_at": 0,
                "expires_at": 0,
            }
        )
        granted.append((gid, item_id, required_level, min_exp, name))
        owned_item_ids.add(item_id)

    if granted or revoked:
        V140_MALL_STATE["inventory"] = [dict(p) for p in V111_INVENTORY]

    return {
        "experience": experience,
        "eligible_ids": eligible_ids,
        "granted": granted,
        "revoked": revoked,
    }


def _v140_select_player(uin):
    uin = _V140_PLAYER_STATE.select(int(uin))
    _v140_expire_due_items(reason="sqlite-player-select-expiry")

    skill_sync = _v170_reconcile_progression_skills()
    skill_grants = list(skill_sync["granted"])
    skill_revokes = list(skill_sync["revoked"])
    skill_changed = bool(skill_grants or skill_revokes)

    preferred = V140_MALL_STATE.get("current_bag_gid")
    selected_gid, changes = _v141_set_current_bag(
        preferred,
        reason="sqlite-player-select",
    )
    if changes or skill_changed:
        save_reason = (
            "sqlite-player-select-skill-reconcile"
            if skill_changed
            else "sqlite-bag-invariant-repair"
        )
        _v140_save_state(save_reason)

    if changes:
        log(
            "MALL-SQLITE",
            f"v4 repaired bag-root state uin={uin} "
            f"current_bag=0x{selected_gid:016x} changes={changes}",
        )

    if skill_changed:
        log(
            "PVE-SKILL",
            "PVE-SKILL-PROGRESSION-v2 reconciled "
            f"uin={uin} exp={int(skill_sync['experience'])} "
            f"granted={len(skill_grants)} revoked={len(skill_revokes)}",
        )
        if skill_grants:
            log(
                "PVE-SKILL",
                "v2 granted: "
                + " | ".join(
                    f"{name}(item={item_id},level={required_level},"
                    f"gid=0x{gid:016x})"
                    for gid, item_id, required_level, _min_exp, name
                    in skill_grants
                ),
            )
        if skill_revokes:
            log(
                "PVE-SKILL",
                "v2 revoked-above-level: "
                + " | ".join(
                    f"{name}(item={item_id},level={required_level},"
                    f"gid=0x{gid:016x})"
                    for gid, item_id, required_level, _min_exp, name
                    in skill_revokes
                ),
            )

    accessory_repairs = _v173_repair_accessory_owners()
    if accessory_repairs:
        _v140_save_state("character-accessory-owner-repair-v173")
        log("MALL", f"v173 repaired character/accessory ownership uin={uin} changes={accessory_repairs}")

    return _V140_PLAYER_STATE.state()


def _v140_next_gid(used=None):
    used = set(used or ())
    used.update(int(p.get("gid", 0)) for p in V111_INVENTORY)
    candidate = int(V140_MALL_STATE.get("next_gid", 0)) & 0xFFFFFFFFFFFFFFFF
    if candidate == 0:
        candidate = ((V109_UIN & 0xFFFFFFFF) << 32) | 0x100

    for _ in range(0x100000):
        if candidate and candidate not in used:
            V140_MALL_STATE["next_gid"] = (candidate + 1) & 0xFFFFFFFFFFFFFFFF
            return candidate
        candidate = (candidate + 1) & 0xFFFFFFFFFFFFFFFF

    raise RuntimeError("v140 could not allocate free PropGID")


def _v140_make_prop(
    gid, item_id, owner_gid=0, location=V109_LOC_BAG,
    duration_hours=V140_ITEM_AVAIL_HOURS, obtained_at=None,
):
    item_id = int(item_id)
    is_role_or_component = (
        _v140_is_role_item(item_id)
        or int(owner_gid) != 0
        or int(V140_ITEM_DEFAULT_LOCATIONS.get(item_id, -1)) < 0
    )
    durability = 0 if is_role_or_component else 100
    duration_hours = int(duration_hours)
    obtained_at = int(time.time() if obtained_at is None else obtained_at)
    expires_at = (
        obtained_at + duration_hours * 3600
        if duration_hours > 0
        else 0
    )
    return {
        "gid": int(gid) & 0xFFFFFFFFFFFFFFFF,
        "item_id": item_id & 0xFFFFFFFF,
        "owner_gid": int(owner_gid) & 0xFFFFFFFFFFFFFFFF,
        "location": int(location) & 0xFF,
        "durability": durability,
        "durability_max": durability,
        "avail_hours": duration_hours,
        "validity": duration_hours,
        "obtained_at": obtained_at,
        "expires_at": expires_at,
        "gain_type": 1,
    }


def _v140_build_commodity_props(
    commodity_id, duration_hours=V140_ITEM_AVAIL_HOURS, obtained_at=None
):
    """Allocate every item belonging to one catalog commodity.

    Character commodities are true bundles in the client data. Example:
      Sofia 200593 -> [100600, 300121, 300122, 100602]

    Role roots are initially stored in the bag. Their following component
    items are owned by that role root so selecting/equipping the role produces
    the complete appearance rather than a naked/default character.
    """
    commodity_id = int(commodity_id)
    duration_hours = int(duration_hours)
    obtained_at = int(time.time() if obtained_at is None else obtained_at)
    items = list(V140_COMMODITY_BUNDLES.get(commodity_id) or ())
    if not items:
        root = V140_SHOP_ITEM_MAP.get(commodity_id)
        if root is None:
            raise KeyError(f"commodity {commodity_id} has no item mapping")
        items = [int(root)]

    used = {int(p.get("gid", 0)) for p in V111_INVENTORY}
    out = []
    active_role_gid = 0

    for item_id in items:
        gid = _v140_next_gid(used)
        used.add(gid)
        default_loc = int(V140_ITEM_DEFAULT_LOCATIONS.get(int(item_id), -1))

        if default_loc in (0x0A, 0x0B):
            # Newly purchased character root remains unequipped until the
            # stock UI sends its normal A008 role/equip operation.
            active_role_gid = gid
            prop = _v140_make_prop(
                gid, item_id,
                owner_gid=0,
                location=V109_LOC_BAG,
                duration_hours=duration_hours,
                obtained_at=obtained_at,
            )
        elif active_role_gid:
            # Character component belongs to the most recent role root.
            comp_loc = 0xFF if default_loc < 0 else (default_loc & 0xFF)
            prop = _v140_make_prop(
                gid, item_id,
                owner_gid=active_role_gid,
                location=comp_loc,
                duration_hours=duration_hours,
                obtained_at=obtained_at,
            )
        else:
            prop = _v140_make_prop(
                gid, item_id,
                owner_gid=0,
                location=V109_LOC_BAG,
                duration_hours=duration_hours,
                obtained_at=obtained_at,
            )

        out.append(prop)

    return out


def _v140_login_prop_groups():
    """Preserve the proven v129 first three groups; append bought props safely."""
    _v140_expire_due_items(reason="login-props-expiry")
    by_gid = {int(p["gid"]): p for p in V111_INVENTORY}
    known_groups = [
        [V109_ROLE_GID, V109_BAG1_GID, V109_BAG2_GID, V109_PRIMARY_GID],
        [V129_SOFIA_HAND_GID, V129_SOFIA_UPPER_GID, V129_SOFIA_HAIR_GID],
        [V127_PISTOL_GID, V127_MELEE_GID, V127_GRENADE_GID],
    ]

    groups = []
    known = set()

    for gids in known_groups:
        rows = []
        for gid in gids:
            p = by_gid.get(int(gid))
            if p is not None:
                rows.append(p)
                known.add(int(gid))
        if rows:
            groups.append(rows)

    extras = [
        p for p in V111_INVENTORY
        if int(p.get("gid", 0)) not in known
    ]
    for i in range(0, len(extras), 5):
        groups.append(extras[i:i+5])

    return groups


def _v13_login_prop_groups_no_roles():
    """
    FIRST-NICKNAME-v13 controlled no-role profile.

    Publish the normal startup profile stream, but withhold character/role
    roots and their component props. Persistent backend inventory is unchanged.
    """
    _v140_expire_due_items(reason="first-login-props-expiry")
    role_gids = {
        int(p.get("gid", 0))
        for p in V111_INVENTORY
        if _v140_is_role_item(int(p.get("item_id", 0)))
    }

    def keep(p):
        gid = int(p.get("gid", 0))
        owner = int(p.get("owner_gid", 0))
        loc = int(p.get("location", -1))
        if gid in role_gids:
            return False

        # PH uses literal root-owner 1 for bags, which can numerically collide
        # with starter role GID 1. Keep normal root/bag rows at loc 0x0C;
        # omit non-bag descendants of role roots (character components).
        if owner in role_gids and loc != V109_LOC_BAG:
            return False
        return True

    visible = [p for p in V111_INVENTORY if keep(p)]
    by_gid = {int(p["gid"]): p for p in visible}

    known_groups = [
        [V109_BAG1_GID, V109_BAG2_GID, V109_PRIMARY_GID],
        [V127_PISTOL_GID, V127_MELEE_GID, V127_GRENADE_GID],
    ]

    groups = []
    known = set()
    for gids in known_groups:
        rows = []
        for gid in gids:
            p = by_gid.get(int(gid))
            if p is not None:
                rows.append(p)
                known.add(int(gid))
        if rows:
            groups.append(rows)

    extras = [
        p for p in visible
        if int(p.get("gid", 0)) not in known
    ]
    for i in range(0, len(extras), 5):
        groups.append(extras[i:i+5])

    omitted = [
        (int(p.get("gid", 0)), int(p.get("item_id", 0)))
        for p in V111_INVENTORY
        if not keep(p)
    ]
    log(
        "ACCOUNT",
        "FIRST-NICKNAME-v13 no-role A006 filter: "
        f"role_gids={[f'0x{x:016x}' for x in sorted(role_gids)]} "
        f"omitted={omitted} visible={len(visible)}",
    )
    return groups


class _v140_ShopReject(Exception):
    def __init__(self, result, message):
        super().__init__(message)
        self.result = int(result) & 0xFFFF
        self.message = str(message)


# Upgrade v139 command registry state for the handlers v140 actually restores.
V139_CURRENT_HANDLER_IDS = frozenset(
    set(V139_CURRENT_HANDLER_IDS)
    | {
        TGAME_ZN_REQ_SHOPCONFHASH,
        TGAME_ZN_REQ_UPDATECOMMODITYFILE,
        TGAME_ZN_REQ_BUYCOMMODITY,
        TGAME_ZN_REQ_TP_BALANCE,
        TGAME_ZN_REQ_ITEM_OPERATION,
        TGAME_ZN_REQ_CHANGE_ROLE,
    }
)
V139_PROTOCOL_ONLY[TGAME_ZN_REQ_SHOPCONFHASH] = (
    "Protocol.ShopConfHash", "CURRENT_BRANCH"
)
V139_PROTOCOL_ONLY[TGAME_ZN_REQ_ITEM_OPERATION] = (
    "Protocol.ItemOperation", "CURRENT_BRANCH"
)

# v22: A146 is now an active current-branch handler.
_v22_change_role_spec = V139_PROTOCOL_REGISTRY["by_cmd"].get(TGAME_ZN_REQ_CHANGE_ROLE)
if _v22_change_role_spec is not None:
    _v22_change_role_spec["status"] = "CURRENT_BRANCH"
    _v22_change_role_spec["implemented"] = True
    _v22_change_role_spec["source"] = "FIRST-NICKNAME-v22 post-A003 A146/A147 completion"

for _cmd in (
    TGAME_ZN_REQ_UPDATECOMMODITYFILE,
    TGAME_ZN_REQ_BUYCOMMODITY,
    TGAME_ZN_REQ_TP_BALANCE,
):
    _spec = V139_PROTOCOL_REGISTRY["by_cmd"].get(_cmd)
    if _spec is not None:
        _spec["status"] = "CURRENT_BRANCH"
        _spec["implemented"] = True
        _spec["source"] = "v140 restored mall handler"




def _v111_pack_inventory_prop(p, session_uin=V109_UIN):
    p = _r13_project_prop(p, session_uin)
    return _v109_pack_prop_info(
        int(p["gid"]),
        int(p["item_id"]),
        owner_gid=int(p.get("owner_gid", 0)),
        location=int(p.get("location", V109_LOC_BAG)),
        durability=int(p.get("durability", 100)),
        durability_max=int(p.get("durability_max", 100)),
        gain_type=int(p.get("gain_type", 0)),
        avail_hours=int(p.get("validity", p.get("avail_hours", V109_ITEM_HOURS))),
        obtain_time=int(p.get("obtained_at", 0) or 0),
        uin=int(session_uin),
    )


def _v127_build_playerprops_chunk(rows, is_last, session_uin=V109_UIN):
    """Build one legal A006 chunk (proto_c2zn declares PropInfo[5])."""
    rows = list(rows)
    if len(rows) > 5:
        raise ValueError(f"A006 chunk exceeds PropInfo[5]: {len(rows)}")
    props = [_v111_pack_inventory_prop(p, session_uin) for p in rows]
    body = (
        _v48_u16(ZONE_ERR_SUCC)
        + _v48_u8(1 if is_last else 0)
        + _v48_i16(len(props))
        + b"".join(props)
    )
    return _v62_build_server_app(
        TGAME_ZN_MAGIC, TGAME_ZN_NTF_PLAYERPROPS, body
    )


def _v140_read_tdr_string(body, off, maxlen):
    if off + 4 > len(body):
        raise ValueError("truncated TDR string length")
    n = struct.unpack_from(">I", body, off)[0]
    off += 4
    if n < 1 or n > maxlen:
        raise ValueError(f"bad TDR string length={n} max={maxlen}")
    if off + n > len(body):
        raise ValueError("truncated TDR string")
    raw = body[off:off+n]
    off += n
    if raw[-1:] != b"\x00":
        raise ValueError("TDR string missing terminal NUL")
    return raw[:-1].decode("latin1", "replace"), off



def _nick_v1_parse_change_nickname(body):
    nickname, off = _v140_read_tdr_string(body, 0, 32)
    if off != len(body):
        raise ValueError(
            f"ChangeNickName trailing bytes={len(body)-off}: {body[off:].hex()}"
        )
    if not nickname:
        raise ValueError("ChangeNickName empty nickname")
    # Keep this first protocol test deliberately conservative.
    try:
        encoded = nickname.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("ChangeNickName v1 test accepts ASCII only") from exc
    if len(encoded) > 31:
        raise ValueError("ChangeNickName nickname exceeds 31 bytes")
    return nickname


def _nick_v1_build_change_nickname_response(
    nickname,
    *,
    result=ZONE_ERR_SUCC,
):
    # ZN2C_ResChangeNickName candidate:
    #   u16 Result | string[32] NewNickName
    body = (
        _v48_u16(int(result) & 0xFFFF)
        + _v50_geo_tdr_string(str(nickname), 32)
    )
    return _v62_build_server_app(
        TGAME_ZN_MAGIC,
        TGAME_ZN_RES_CHANGE_NICKNAME_TEST,
        body,
    )


def _v140_parse_shop_conf_hash(body):
    if len(body) != 4:
        raise ValueError(f"ShopConfHash must be 4B, got {len(body)}")
    return struct.unpack(">I", body)[0]


def _v140_build_shop_conf_hash_response(client_hash):
    # ZN2C_ResShopConfHash:
    #   u16 Result | u32 ServerHash | string[256] Url
    body = (
        _v48_u16(SHOP_ERR_SUCC)
        + _v48_u32(int(client_hash) & 0xFFFFFFFF)
        + _v50_geo_tdr_string("", 256)
    )
    return _v62_build_server_app(
        TGAME_ZN_MAGIC, TGAME_ZN_RES_SHOPCONFHASH, body
    )


def _v140_parse_buy_commodity(body):
    # C2ZN_ReqBuyCommodity:
    # u16 BuyType | u64 Consignne | string[32] NickName | u16 Count |
    # {u32 CommodityId,u16 PriceIndex,u32 Price,u32 VoucherId}[Count] |
    # u16 PayType | u32 ConvertMP | string[256] Remark
    if len(body) < 16:
        raise ValueError(f"BuyCommodity body too short: {len(body)}B")

    off = 0
    buy_type = struct.unpack_from(">H", body, off)[0]
    off += 2
    consignne = struct.unpack_from(">Q", body, off)[0]
    off += 8
    nickname, off = _v140_read_tdr_string(body, off, 32)

    if off + 2 > len(body):
        raise ValueError("BuyCommodity missing Count")
    count = struct.unpack_from(">H", body, off)[0]
    off += 2
    if count > 20:
        raise ValueError(f"BuyCommodity Count={count} exceeds 20")

    commodities = []
    for _ in range(count):
        if off + 14 > len(body):
            raise ValueError("BuyCommodity truncated commodity row")
        commodity_id = struct.unpack_from(">I", body, off)[0]
        off += 4
        price_index = struct.unpack_from(">H", body, off)[0]
        off += 2
        client_price = struct.unpack_from(">I", body, off)[0]
        off += 4
        voucher_id = struct.unpack_from(">I", body, off)[0]
        off += 4
        commodities.append({
            "commodity_id": commodity_id,
            "price_index": price_index,
            "client_price": client_price,
            "voucher_id": voucher_id,
        })

    if off + 6 > len(body):
        raise ValueError("BuyCommodity missing PayType/ConvertMP")
    pay_type = struct.unpack_from(">H", body, off)[0]
    off += 2
    convert_mp = struct.unpack_from(">I", body, off)[0]
    off += 4
    remark, off = _v140_read_tdr_string(body, off, 256)

    if off != len(body):
        raise ValueError(f"BuyCommodity trailing bytes={len(body)-off}")

    return {
        "buy_type": buy_type,
        "consignne": consignne,
        "nickname": nickname,
        "count": count,
        "commodities": commodities,
        "pay_type": pay_type,
        "convert_mp": convert_mp,
        "remark": remark,
    }


def _v140_expected_pay_type(currency):
    return {"GP": PAY_GP, "TP": PAY_TP, "MP": PAY_MP}.get(str(currency))


def _v140_price(commodity_id, price_index):
    row = V140_SHOP_PRICES.get(int(commodity_id))
    if row is None:
        raise _v140_ShopReject(
            SHOP_ERR_COMMODITY_NOTEXIST,
            f"unknown commodity={commodity_id}",
        )

    currency, prices = row
    idx = int(price_index)
    if idx < 0 or idx >= len(prices):
        raise _v140_ShopReject(
            SHOP_ERR_COMMODITY_PERIODINVALID,
            f"commodity={commodity_id} invalid price_index={idx}/{len(prices)}",
        )
    return str(currency), int(prices[idx])


def _v140_duration_hours(commodity_id, price_index):
    periods = V140_SHOP_AVAIL_HOURS.get(int(commodity_id))
    idx = int(price_index)
    if periods is None or idx < 0 or idx >= len(periods):
        raise _v140_ShopReject(
            SHOP_ERR_COMMODITY_PERIODINVALID,
            f"commodity={commodity_id} has no validity for price_index={idx}",
        )
    return int(periods[idx])


def _v140_plan_purchase(req, self_uin=V109_UIN):
    if int(req.get("count", 0)) <= 0 or not req.get("commodities"):
        raise _v140_ShopReject(SHOP_ERR_SHOPCART_EMPTY, "empty cart")

    # v164: BuyType is opaque stock-client purchase-mode metadata.
    #
    # Do not whitelist BuyType values or tie purchase handling to particular
    # commodities/weapons. Direct purchases, recommended-item multi-buy, and
    # shopping-cart purchases all use the same generic atomic planner.
    #
    # Authorization is based on Consignne below. Every commodity row is still
    # validated server-side for ID, price index/period, currency, voucher,
    # ConvertMP and wallet balance before anything is committed.
    buy_type = int(req.get("buy_type", 0)) & 0xFFFF

    self_uin = int(self_uin) & 0xFFFFFFFF
    consignne = int(req.get("consignne") or self_uin)
    if consignne not in (0, self_uin):
        raise _v140_ShopReject(
            SHOP_ERR_FAIL,
            f"gift/other-user purchase not enabled; consignne={consignne}",
        )

    if int(req.get("convert_mp", 0)) != 0:
        raise _v140_ShopReject(
            SHOP_ERR_PAYTYPE_INVALID,
            f"ConvertMP={req.get('convert_mp')} is not implemented",
        )

    pay_type = int(req.get("pay_type", 0))
    totals = {"TP": 0, "GP": 0, "MP": 0}
    staged = []

    for c in req["commodities"]:
        cid = int(c["commodity_id"])
        pidx = int(c["price_index"])

        if cid not in V140_SHOP_ITEM_MAP:
            raise _v140_ShopReject(
                SHOP_ERR_COMMODITY_NOTEXIST,
                f"commodity={cid} missing item map",
            )

        currency, server_price = _v140_price(cid, pidx)
        duration_hours = _v140_duration_hours(cid, pidx)
        required = _v140_expected_pay_type(currency)
        if pay_type != required:
            raise _v140_ShopReject(
                SHOP_ERR_PAYTYPE_INVALID,
                f"commodity={cid} currency={currency} "
                f"requires pay_type={required}, got {pay_type}",
            )

        if int(c.get("voucher_id", 0)) != 0:
            raise _v140_ShopReject(
                SHOP_ERR_PAYTYPE_INVALID,
                f"voucher_id={c['voucher_id']} not implemented",
            )

        totals[currency] += server_price
        props = _v140_build_commodity_props(
            cid, duration_hours=duration_hours, obtained_at=int(time.time())
        )

        staged.append({
            "commodity_id": cid,
            "commodity_name": V140_COMMODITY_NAMES.get(cid, ""),
            "price_index": pidx,
            "currency": currency,
            "server_price": server_price,
            "client_price": int(c.get("client_price", 0)),
            "props": props,
        })

    wallet = _v140_wallet()
    if totals["TP"] > int(wallet["ap"]):
        raise _v140_ShopReject(
            SHOP_ERR_NOTENOUGHMONEY,
            f"not enough AP need={totals['TP']} have={wallet['ap']}",
        )
    if totals["GP"] > int(wallet["gp"]):
        raise _v140_ShopReject(
            SHOP_ERR_NOTENOUGHMONEY,
            f"not enough GP need={totals['GP']} have={wallet['gp']}",
        )
    if totals["MP"] > int(wallet["mp"]):
        raise _v140_ShopReject(
            SHOP_ERR_NOTENOUGHMONEY,
            f"not enough MP need={totals['MP']} have={wallet['mp']}",
        )

    return {
        "staged": staged,
        "consume_tp": totals["TP"],
        "consume_gp": totals["GP"],
        "consume_mp": totals["MP"],
    }


def _v140_build_buy_response(
    req,
    staged,
    result=SHOP_ERR_SUCC,
    consume_tp=0,
    consume_gp=0,
    consume_mp=0,
    self_uin=V109_UIN,
):
    # ZN2C_ResBuyCommodity:
    # Result, BuyType, PayType, NickName, ConsumeTP, TPBalance,
    # ConsumeGP, ConsumeMP, Count, ShopResBuyCommodity[Count], ConsignneUin.
    parts = []

    for row in staged:
        prop_rows = []
        for prop in row.get("props", []):
            prop_rows.append(
                _v48_u64(_r13_wire_gid(prop["gid"], self_uin))
                + _v48_u32(prop["item_id"])
                + _v48_u32(prop.get("avail_hours", V140_ITEM_AVAIL_HOURS))
            )

        parts.append(
            _v48_u32(row["commodity_id"])
            + _v48_u16(row["price_index"])
            + _v48_u32(len(prop_rows))
            + b"".join(prop_rows)
        )

    body = (
        _v48_u16(result)
        + _v48_u16(int(req.get("buy_type", 1)))
        + _v48_u16(int(req.get("pay_type", 0)))
        + _v50_geo_tdr_string(req.get("nickname", ""), 32)
        + _v48_u32(int(consume_tp))
        + _v48_u32(int(_v140_wallet()["ap"]))
        + _v48_u32(int(consume_gp))
        + _v48_u32(int(consume_mp))
        + _v48_u16(len(parts))
        + b"".join(parts)
        + _v48_u64(int(req.get("consignne") or self_uin))
    )

    return _v62_build_server_app(
        TGAME_ZN_MAGIC, TGAME_ZN_RES_BUYCOMMODITY, body
    )


def _v140_build_update_player_property(update_flag, reason):
    wallet = _v140_wallet()
    experience = (
        int(V140_MALL_STATE.get("experience", 0))
        if int(update_flag) & UPDATE_FLAG_EXP
        else 0
    )
    body = (
        _v48_u32(update_flag)
        + _v48_u16(reason)
        + _v48_i32(int(wallet["ap"]))
        + _v48_i32(0)                 # HappyPoint
        + _v48_i32(int(wallet["gp"]))
        + _v48_i32(int(wallet["mp"]))
        + _v48_i32(experience)        # Persisted total; client derives displayed level
        + _v48_i32(0)                 # EvolutionPoint
        + _v48_i32(0)                 # CardPoint
        + _v48_u16(0)                 # UpdateProp count
    )
    if len(body) != 36:
        raise AssertionError(f"A00A UpdatePlayerProperty body len={len(body)}")
    return _v62_build_server_app(
        TGAME_ZN_MAGIC,
        TGAME_ZN_NTF_UPDATE_PLAYER_PROPERTY,
        body,
    )


def _v140_build_authoritative_wallet_refresh():
    """Build read-only AP/GP/MP refresh notifications from the current wallet."""
    specs = (
        (UPDATE_FLAG_TP, "AP", UPDATE_REASON_TP_BALANCE),
        (UPDATE_FLAG_GP, "GP", 0),
        (UPDATE_FLAG_MP, "MP", 0),
    )
    return tuple(
        (
            flag,
            name,
            reason,
            _v140_build_update_player_property(flag, reason),
        )
        for flag, name, reason in specs
    )


V140_MONEYFLOW_REPLAY_LIMIT = 360


def _v140_moneyflow_datetime_now(epoch=None):
    """Serialize one PH/TDR datetime scalar for Consumer List rows.

    TDR type 0x17 is an 8-byte scalar. Build the native x86 structure first,
    then byte-swap the whole scalar for the wire.
    """
    tm = time.localtime(
        time.time() if epoch is None else int(epoch)
    )
    host = struct.pack(
        "<hBBhBB",
        int(tm.tm_year),
        int(tm.tm_mon),
        int(tm.tm_mday),
        int(tm.tm_hour),
        int(tm.tm_min),
        int(tm.tm_sec),
    )
    raw = host[::-1]
    if len(raw) != 8:
        raise AssertionError(
            f"money-flow datetime wire size {len(raw)} != 8"
        )
    return raw


def _v140_pack_moneyflow_record(
    uin,
    money_type,
    number,
    current,
    *,
    reason=MONEYREASON_BUY,
    when=None,
):
    """Build one stock PH PlayerMoneyFlow record (26 bytes)."""
    dt = bytes(when) if when is not None else _v140_moneyflow_datetime_now()
    if len(dt) != 8:
        raise ValueError(f"money-flow datetime must be 8B, got {len(dt)}")
    raw = (
        _v48_u64(int(uin))
        + dt
        + _v48_u8(int(money_type))
        + _v48_i32(int(number))
        + _v48_i32(int(current))
        + _v48_u8(int(reason))
    )
    if len(raw) != 26:
        raise AssertionError(f"PlayerMoneyFlow wire size {len(raw)} != 26")
    return raw


def _v140_build_moneyflow_notification(records):
    """Build verified ZN2C_NtfMoneyFlow (0xA367)."""
    records = [bytes(row) for row in records]
    if len(records) > 90:
        raise ValueError("too many money-flow rows")
    for row in records:
        if len(row) != 26:
            raise ValueError(f"bad PlayerMoneyFlow row size={len(row)}")
    body = _v48_u32(len(records)) + b"".join(records)
    return _v62_build_server_app(
        TGAME_ZN_MAGIC,
        TGAME_ZN_NTF_MONEYFLOW,
        body,
    )


def _v140_make_purchase_moneyflow_rows(
    *,
    session_uin,
    consume_tp,
    consume_gp,
    consume_mp,
    occurred_at=None,
    details="",
    commodity_ids=(),
):
    """Create DB/wire rows from the authoritative post-purchase wallet."""
    occurred_at = int(
        time.time() if occurred_at is None else occurred_at
    )
    wallet = _v140_wallet()
    details = str(details or "")
    commodity_ids = [int(value) for value in commodity_ids]
    rows = []

    for money_type, amount, current in (
        (MONEYTYPE_TP, int(consume_tp), int(wallet["ap"])),
        (MONEYTYPE_GP, int(consume_gp), int(wallet["gp"])),
        (MONEYTYPE_MP, int(consume_mp), int(wallet["mp"])),
    ):
        if amount <= 0:
            continue
        rows.append(
            {
                "uin": int(session_uin),
                "occurred_at": occurred_at,
                "money_type": int(money_type),
                "number": -amount,
                "current": current,
                "reason": MONEYREASON_BUY,
                "details": details,
                "commodity_ids": list(commodity_ids),
            }
        )
    return rows


def _v140_send_moneyflow_rows(
    conn,
    key,
    label,
    rows,
    *,
    source,
):
    """Send persisted/live money-flow rows in the stock maximum of 90/packet."""
    rows = [dict(row) for row in rows]
    if not rows:
        return 0

    sent = 0
    chunks = [rows[i:i + 90] for i in range(0, len(rows), 90)]
    for chunk_index, chunk in enumerate(chunks):
        records = [
            _v140_pack_moneyflow_record(
                int(row.get("uin", _V140_PLAYER_STATE.current_uin())),
                int(row["money_type"]),
                int(row["number"]),
                int(row["current"]),
                reason=int(row.get("reason", MONEYREASON_BUY)),
                when=_v140_moneyflow_datetime_now(
                    int(row.get("occurred_at", time.time()))
                ),
            )
            for row in chunk
        ]
        pkt = _v140_build_moneyflow_notification(records)
        summary = ",".join(
            f"{int(row['money_type'])}:{int(row['number'])}"
            f"->{int(row['current'])}"
            for row in chunk
        )
        _v48_send_app(
            conn,
            key,
            pkt,
            label,
            "ZN2C_NTF_MONEYFLOW "
            "CONSUMER-LIST-A367-PERSIST-v1 "
            f"source={source} "
            f"chunk={chunk_index + 1}/{len(chunks)} "
            f"count={len(chunk)} rows={summary}",
        )
        sent += len(chunk)
    return sent


def _v140_replay_moneyflow(conn, key, label, *, session_uin):
    """Replay persisted Consumer List history after the stock profile is ready."""
    rows = PLAYER_DB.load_moneyflow(
        int(session_uin),
        limit=V140_MONEYFLOW_REPLAY_LIMIT,
    )
    for row in rows:
        row["uin"] = int(session_uin)
    sent = _v140_send_moneyflow_rows(
        conn,
        key,
        label,
        rows,
        source="sqlite-login-replay",
    )
    log(
        "MALL-SQLITE",
        f"Consumer List replay uin={int(session_uin)} "
        f"rows={sent} limit={V140_MONEYFLOW_REPLAY_LIMIT}",
    )
    return sent


def _v140_send_wallet_sync(conn, key, label, reason=UPDATE_REASON_BUY, prefix="mall"):
    for flag, name in (
        (UPDATE_FLAG_TP, "AP"),
        (UPDATE_FLAG_GP, "GP"),
        (UPDATE_FLAG_MP, "MP"),
    ):
        why = UPDATE_REASON_TP_BALANCE if flag == UPDATE_FLAG_TP and reason != UPDATE_REASON_BUY else reason
        pkt = _v140_build_update_player_property(flag, why)
        _v48_send_app(
            conn, key, pkt, label,
            f"ZN2C_NTF_UPDATEPLAYERPROPERTY v140 {prefix} "
            f"flag={name} AP={_v140_wallet()['ap']} "
            f"GP={_v140_wallet()['gp']} MP={_v140_wallet()['mp']} "
            f"reason=0x{why:02x}",
        )


def _v140_send_experience_sync(conn, key, label, reason=0):
    """Send stored EXP so the client can derive and display the player's level."""
    experience = int(V140_MALL_STATE.get("experience", 0))
    pkt = _v140_build_update_player_property(UPDATE_FLAG_EXP, reason)
    _v48_send_app(
        conn, key, pkt, label,
        f"ZN2C_NTF_UPDATEPLAYERPROPERTY v140 login flag=EXP "
        f"experience={experience} reason=0x{int(reason):08x}",
    )


def _v140_send_full_inventory(
    conn, key, label, prefix="mall", session_uin=V109_UIN
):
    # Normalize every A006 snapshot. Old inventory rows can have Bag 1 and a
    # purchased backpack both mounted as owner=1, which makes the client infer
    # the wrong DefaultBagIndex when Storage is reopened.
    selected_bag_gid, bag_changes = _v141_set_current_bag(
        V140_MALL_STATE.get("current_bag_gid"),
        reason=f"{prefix}-inventory-publish",
    )
    if bag_changes:
        _v140_save_state(f"{prefix}-bag-invariant")
    mounted_bag_gids = [
        int(prop["gid"]) for prop in _v141_bag_props()
        if int(prop.get("owner_gid", 0)) == V110_BAG_MOUNT_OWNER
    ]
    log(
        "MALL-BAG",
        f"v156 A006 inventory publish uin={session_uin} prefix={prefix} "
        f"selected=0x{selected_bag_gid:016x} "
        f"owned_bags={len(_v141_bag_props())} "
        f"mounted={[f'0x{gid:016x}' for gid in mounted_bag_gids]} "
        f"changes={len(bag_changes)}",
    )

    rows = list(V111_INVENTORY)
    chunks = [rows[i:i+5] for i in range(0, len(rows), 5)] or [[]]

    for i, chunk in enumerate(chunks):
        pkt = _v127_build_playerprops_chunk(
            chunk,
            i == len(chunks) - 1,
            session_uin=session_uin,
        )
        _v48_send_app(
            conn, key, pkt, label,
            f"ZN2C_NTF_PLAYERPROPS v140 {prefix} "
            f"chunk={i+1}/{len(chunks)} count={len(chunk)} "
            f"is_last={int(i == len(chunks)-1)}",
        )


def _v140_build_update_commodity_response():
    # UTGame.u callback is OnTGOnlineDelegate_UpdateFPSCommodityFromServer(ErrorCode).
    return _v62_build_server_app(
        TGAME_ZN_MAGIC,
        TGAME_ZN_RES_UPDATECOMMODITYFILE,
        _v48_u16(SHOP_ERR_SUCC),
    )


def _v140_build_item_operation_response(op_body):
    op_body = bytes(op_body)
    if len(op_body) != 19:
        raise ValueError(f"A201 operation body must be 19B, got {len(op_body)}")
    return _v62_build_server_app(
        TGAME_ZN_MAGIC,
        TGAME_ZN_RES_ITEM_OPERATION,
        _v48_u16(ZONE_ERR_SUCC) + op_body,
    )




# v160 Item-tab support.
V160_RENAME_CARD_ITEM_ID = 100181
V160_CLEAR_RECORD_CARD_ITEM_ID = 100182
V160_CLEAR_WINLOSE_CARD_ITEM_ID = 100196
V160_REGULAR_EXP_CARD_ITEM_ID = 100059
V160_ADVANCED_EXP_CARD_ITEM_ID = 100060


def _v160_build_result_only_response(command_id, result=ZONE_ERR_SUCC):
    return _v62_build_server_app(
        TGAME_ZN_MAGIC,
        int(command_id) & 0xFFFF,
        _v48_u16(int(result) & 0xFFFF),
    )


def _v160_parse_use_card(body):
    if len(body) != 8:
        raise ValueError(f"A347 UseCard body must be exactly 8B, got {len(body)}")
    func_type, sub_func_type = struct.unpack(">ii", body)
    return int(func_type), int(sub_func_type)


def _v160_find_inventory_item(item_id):
    item_id = int(item_id)
    candidates = [
        p for p in V111_INVENTORY
        if int(p.get("item_id", 0)) == item_id
        and not _v140_prop_is_expired(p)
    ]
    if not candidates:
        return None

    def _sort_key(prop):
        exp = int(prop.get("expires_at", 0) or 0)
        return (
            exp <= 0,
            exp if exp > 0 else 0x7FFFFFFFFFFFFFFF,
            int(prop["gid"]),
        )

    return min(candidates, key=_sort_key)


def _v160_consume_inventory_item(item_id, reason):
    prop = _v160_find_inventory_item(item_id)
    if prop is None:
        return None

    gid = int(prop["gid"])
    removed = {gid}
    while True:
        children = {
            int(p.get("gid", 0))
            for p in V111_INVENTORY
            if int(p.get("owner_gid", 0)) in removed
            and int(p.get("gid", 0)) != 0
        }
        expanded = removed | children
        if expanded == removed:
            break
        removed = expanded

    V111_INVENTORY[:] = [
        p for p in V111_INVENTORY
        if int(p.get("gid", 0)) not in removed
    ]
    _v140_save_state(reason)
    return prop


def _v160_activate_known_function_card(func_type, sub_func_type):
    if int(func_type) != 0:
        return None, "unsupported FunctionType"

    item_id = {
        0: V160_REGULAR_EXP_CARD_ITEM_ID,
        1: V160_ADVANCED_EXP_CARD_ITEM_ID,
    }.get(int(sub_func_type))
    if item_id is None:
        return None, "unsupported ExpAcceleration SubFunctionType"

    prop = _v160_find_inventory_item(item_id)
    if prop is None:
        return None, f"required item {item_id} is not owned"

    default_loc = int(V140_ITEM_DEFAULT_LOCATIONS.get(item_id, -1))
    if default_loc < 0 or default_loc > 0xFF:
        return None, f"item {item_id} has no usable catalog slot"

    prop["owner_gid"] = V110_BAG_MOUNT_OWNER
    prop["location"] = default_loc & 0xFF
    _v140_save_state("A347-use-function-card")
    return prop, (
        f"activated item={item_id} gid=0x{int(prop['gid']):016x} "
        f"slot=0x{default_loc:02x}"
    )


def _v109_build_starter_playerprops(seq):
    """Compatibility helper: only valid when inventory fits one A006."""
    if len(V111_INVENTORY) > 5:
        raise ValueError(
            "starter inventory now requires chunked A006; use "
            "_v127_build_playerprops_chunk()"
        )
    return _v127_build_playerprops_chunk(V111_INVENTORY, True)


def _v111_parse_prop_operation(body):
    # C2ZN_ReqPropOperation = u16 Operation + u64 SubjectGID +
    # u64 TargetGID + u8 Location = exactly 19 bytes.
    if len(body) != 19:
        raise ValueError(f"PropOperation must be exactly 19B, got {len(body)}")
    return {
        "operation": struct.unpack_from(">H", body, 0)[0],
        "subject_gid": struct.unpack_from(">Q", body, 2)[0],
        "target_gid": struct.unpack_from(">Q", body, 10)[0],
        "location": body[18],
    }


def _v111_pack_prop_operation(op):
    return struct.pack(
        ">HQQB",
        int(op["operation"]) & 0xFFFF,
        int(op["subject_gid"]) & 0xFFFFFFFFFFFFFFFF,
        int(op["target_gid"]) & 0xFFFFFFFFFFFFFFFF,
        int(op["location"]) & 0xFF,
    )


def _v111_build_prop_operation_response(op_body):
    op_body = bytes(op_body)
    if len(op_body) != 19:
        raise ValueError("A009 operation body must be 19B")
    return _v62_build_server_app(
        TGAME_ZN_MAGIC,
        TGAME_ZN_RES_PROP_OPERATION,
        _v48_u16(ZONE_ERR_SUCC) + op_body,
    )


def _v111_build_prop_operation_notification(op_body):
    op_body = bytes(op_body)
    if len(op_body) != 19:
        raise ValueError("A00A operation body must be 19B")
    return _v62_build_server_app(
        TGAME_ZN_MAGIC,
        TGAME_ZN_NTF_PROP_OPERATION,
        op_body,
    )



def _v143b_resolve_null_subject_unequip(op):
    """Resolve stock-PH null-subject Remove/Unequip into a real equipped GID.

    Live PH melee Remove arrives as op=0, subject=0, target=<bag>, location=0.
    v161 is catalog-driven instead of hard-coding MK4/Jungle Bolo (100058),
    and also recovers purchased melee rows left at legacy Location=Bag.
    """
    if int(op.get("operation", -1)) != PROP_OP_EQUIP:
        return None
    if int(op.get("subject_gid", 0)) != 0:
        return None

    target_bag = int(op.get("target_gid", 0))
    req_loc = int(op.get("location", V109_LOC_BAG))
    if target_bag not in _v141_bag_gids():
        return None

    def _catalog_slot(prop):
        try:
            return int(
                V140_ITEM_DEFAULT_LOCATIONS.get(
                    int(prop.get("item_id", 0)), -1
                )
            )
        except Exception:
            return -1

    def _pick_catalog_slot(slot, allow_legacy_bag=False):
        exact = [
            p for p in V111_INVENTORY
            if int(p.get("owner_gid", 0)) == target_bag
            and int(p.get("location", V109_LOC_BAG)) == int(slot)
            and _catalog_slot(p) == int(slot)
        ]
        if exact:
            exact.sort(key=lambda p: int(p.get("gid", 0)))
            return exact[0], "canonical"

        if allow_legacy_bag:
            legacy = [
                p for p in V111_INVENTORY
                if int(p.get("owner_gid", 0)) == target_bag
                and int(p.get("location", V109_LOC_BAG)) == V109_LOC_BAG
                and _catalog_slot(p) == int(slot)
            ]
            if legacy:
                legacy.sort(key=lambda p: int(p.get("gid", 0)))
                return legacy[0], f"legacy-bag candidates={len(legacy)}"

        return None, None

    def _canonical_takeoff(item, slot, source, kind):
        effective = {
            "operation": PROP_OP_TAKEOFF,
            "subject_gid": int(item["gid"]),
            "target_gid": 0,
            "location": V109_LOC_BAG,
        }
        return item, effective, (
            f"v161 null-subject {kind} remove -> canonical takeoff "
            f"gid=0x{int(item['gid']):016x} "
            f"item={int(item.get('item_id', 0))} "
            f"catalog_slot=0x{int(slot):02x} source={source}"
        )

    if req_loc == V109_LOC_PRIMARY:
        melee, source = _pick_catalog_slot(
            V127_LOC_MELEE,
            allow_legacy_bag=True,
        )
        if melee is not None:
            return _canonical_takeoff(
                melee, V127_LOC_MELEE, source, "melee"
            )

    if req_loc in (V127_LOC_PISTOL, V127_LOC_MELEE, V127_LOC_GRENADE):
        item, source = _pick_catalog_slot(
            req_loc,
            allow_legacy_bag=True,
        )
        if item is not None:
            return _canonical_takeoff(
                item, req_loc, source, "slot"
            )

    return None


def _v111_apply_prop_operation(op):
    """Apply one live A008 operation to the v110 starter inventory.

    Backpack entitlement props (Bag1/Bag2) are non-exclusive structural
    mounts: both may have owner=1/location=Bag simultaneously.

    The only starter weapon currently published is QBS09 item 100497, whose
    canonical equipment slot is Primary (0). If the client asks to equip that
    weapon to a bag using generic Location=Bag, normalize it to Primary.
    """
    accessory = _v173_apply_accessory_equip(op)
    if accessory is not None:
        return accessory

    eff = dict(op)
    gid = int(op["subject_gid"])
    subject = next((p for p in V111_INVENTORY if int(p["gid"]) == gid), None)

    # v143b: stock PH can encode the melee Remove/Unequip click as
    # EQUIP(subject=0,target=current-bag,loc=0). Resolve that alternate
    # retail form before the normal unknown-GID ACK-only path.
    if subject is None and gid == 0:
        resolved = _v143b_resolve_null_subject_unequip(op)
        if resolved is not None:
            subject, eff, action = resolved
            subject["owner_gid"] = 0
            subject["location"] = V109_LOC_BAG
            return (
                f"{action}; inventory owner=0x0000000000000000 "
                f"loc=0x{V109_LOC_BAG:02x}"
            ), eff

    if subject is None:
        return "subject GID not in starter inventory (ACK only)", eff

    if op["operation"] == PROP_OP_DROP:
        # Keep the role and every catalog-recognized backpack root.
        if gid == V109_ROLE_GID or _v141_is_bag_item(
            subject.get("item_id", 0)
        ):
            return "drop ignored for structural starter prop", eff
        V111_INVENTORY[:] = [
            p for p in V111_INVENTORY if int(p["gid"]) != gid
        ]
        return "drop removed item", eff

    if op["operation"] == PROP_OP_TAKEOFF:
        # v116: live PH-client captures from the earlier unlocked implementation
        # prove a weapon takeoff becomes:
        #
        #     owner_gid = 0
        #     location  = Bag (0x0C)
        #
        # After that state is published back in A006, the stock client naturally
        # sends a new EQUIP A008 for the weapon:
        #
        #     subject = weapon GID
        #     target  = selected Bag GID
        #     location = Bag (0x0C)
        #
        # The server then maps that generic Bag request to the weapon's canonical
        # equipment socket (QBS09 -> Primary / 0x00).
        #
        # v115 incorrectly kept owner_gid=<old Bag GID> on takeoff, which left the
        # weapon logically attached to Bag1 and prevented us from observing the
        # normal re-equip transition in the current test.
        subject["owner_gid"] = 0
        subject["location"] = V109_LOC_BAG
        eff["target_gid"] = 0
        eff["location"] = V109_LOC_BAG
        return (
            f"takeoff -> inventory owner=0x0000000000000000 "
            f"loc=0x{V109_LOC_BAG:02x}"
        ), eff

    if op["operation"] != PROP_OP_EQUIP:
        return f"unknown operation={op['operation']}", eff

    requested_owner = int(op["target_gid"])
    requested_location = int(op["location"])
    item_id = int(subject["item_id"])

    # v140: character roots are not ordinary bag equipment.
    # The catalog's canonical item location tells us whether a purchased
    # character belongs in Role1 (0x0A) or Role2 (0x0B).  The stock UI's
    # current-role/equip actions arrive through this same proven A008 path.
    role_slot = _v140_role_slot(item_id)
    if role_slot is not None:
        # Unmount any other role occupying the same role slot.
        for other in V111_INVENTORY:
            if other is subject:
                continue
            other_item = int(other.get("item_id", 0))
            if (
                _v140_role_slot(other_item) == role_slot
                and int(other.get("owner_gid", 0)) != 0
                and int(other.get("location", V109_LOC_BAG)) == role_slot
            ):
                other["owner_gid"] = 0
                other["location"] = V109_LOC_BAG

        subject["owner_gid"] = V110_BAG_MOUNT_OWNER
        subject["location"] = role_slot
        eff["target_gid"] = V110_BAG_MOUNT_OWNER
        eff["location"] = role_slot

        V140_MALL_STATE["current_role_gid"] = int(subject["gid"])
        return (
            f"role-equip current_role=0x{int(subject['gid']):016x} "
            f"item={item_id} slot=0x{role_slot:02x}"
        ), eff

    # Client's live bag-selection packet is:
    #   BagGID -> target literal 1, Location=Bag.
    #
    # v141: selecting any owned backpack is exclusive. Mount it to root and
    # unmount all other owned bags so GetCharInfo has one DefaultBagIndex.
    if _v141_is_bag_item(item_id):
        selected_gid, bag_changes = _v141_set_current_bag(
            int(subject["gid"]),
            reason="A008-bag-select",
        )
        owner_gid = V110_BAG_MOUNT_OWNER
        location = V109_LOC_BAG
        owner_source = (
            f"bag-select current=0x{selected_gid:016x} "
            f"exclusive changes={len(bag_changes)}"
        )
    else:
        valid_bags = _v141_bag_gids()
        if requested_owner in valid_bags:
            owner_gid = requested_owner
            owner_source = "client-bag"
        elif requested_owner in (0, V109_ROLE_GID):
            owner_gid = _v141_current_bag_gid()
            owner_source = "fallback-current-bag"
        else:
            owner_gid = requested_owner
            owner_source = "client"

        location = requested_location
        # v127: normalize a generic Bag equip to each starter weapon's real
        # bag-local socket (Primary/Pistol/Melee/Grenade).
        canonical_slot = V127_STARTER_WEAPON_SLOTS.get(item_id)
        if canonical_slot is not None and location == V109_LOC_BAG:
            location = canonical_slot

        # v160: Item-tab props use catalog-defined sockets. Canonicalize only
        # a generic Location=Bag request; explicit client locations remain.
        catalog_slot = int(V140_ITEM_DEFAULT_LOCATIONS.get(item_id, -1))
        if (
            location == V109_LOC_BAG
            and not _v140_is_role_item(item_id)
            and not _v141_is_bag_item(item_id)
            and 0 <= catalog_slot <= 0xFF
            and catalog_slot not in (
                V109_LOC_ROLE1,
                0x0B,
                V109_LOC_BAG,
            )
        ):
            location = catalog_slot

        # Real equipment sockets are exclusive inside one bag/root.
        if location != V109_LOC_BAG:
            for other in V111_INVENTORY:
                if other is subject:
                    continue
                if (
                    int(other.get("owner_gid", 0)) == owner_gid
                    and int(other.get("location", V109_LOC_BAG)) == location
                ):
                    other["owner_gid"] = 0
                    other["location"] = V109_LOC_BAG

    subject["owner_gid"] = owner_gid
    subject["location"] = location
    eff["target_gid"] = owner_gid
    eff["location"] = location

    return (
        f"equip owner=0x{owner_gid:016x} ({owner_source}) "
        f"req_loc=0x{requested_location:02x} stored_loc=0x{location:02x}"
    ), eff


def _v111_inventory_summary():
    parts = []
    for p in V111_INVENTORY:
        parts.append(
            f"item={int(p['item_id'])} gid=0x{int(p['gid']):016x} "
            f"owner=0x{int(p.get('owner_gid',0)):016x} "
            f"loc=0x{int(p.get('location',V109_LOC_BAG)):02x}"
        )
    return " | ".join(parts)


def _v124_build_bag1_refresh_notification():
    """Publish the same authoritative Bag1 equip state produced by a manual click.

    IMPORTANT: this deliberately does NOT add any new PropInfo rows.  The v123
    trace proved that expanding the login A006 from 4 props to 7 props blocks
    the stock PH client's natural Chief A008/role-commit path and leaves it on
    the launcher splash.  v124 keeps the proven four-prop login contract intact
    and only refreshes Bag1 after Chief has completed A008/A009/A00A.
    """
    op = {
        "operation": PROP_OP_EQUIP,
        "subject_gid": V109_BAG1_GID,
        "target_gid": V110_BAG_MOUNT_OWNER,
        "location": V109_LOC_BAG,
    }
    return _v111_build_prop_operation_notification(
        _v111_pack_prop_operation(op)
    )

def _v48_player_info(uin=10001, nickname="LocalPlayer", cur_role_gid=None, player_state=None):
    # Exact field order recovered from PlayerInfo metalib. v70 uses the runtime-verified\n    # TDR string form for NickName: u32_be(strlen+1) + NUL-terminated bytes.\n    # CurRoleGID/RoleType
    # v140 resolves the active role and wallet from persistent mall state when omitted.
    if cur_role_gid is None:
        cur_role_gid = _v140_current_role_gid() if player_state is None else _r13_wire_gid(player_state["current_role_gid"], uin)
    wallet = _v140_wallet() if player_state is None else player_state["wallet"]
    experience = int((V140_MALL_STATE if player_state is None else player_state).get("experience", 0))
    clan = CLAN_DB.get_player_clan(uin)
    return (
        _v48_u64(uin)
        + _v48_u32(0)
        + _v50_geo_tdr_string(nickname, 32)
        + _v48_i32(int(wallet["ap"])) + _v48_i32(int(wallet["gp"]))
        + _v48_i32(int(wallet["mp"])) + _v48_i32(0)
        + _v48_u32(0) + _v48_u16(0)
        + _v48_i32(experience)  # Persisted cumulative Experience
        + _v48_dt_zero() + _v48_dt_zero()
        + _v48_u64(cur_role_gid)  # CurRoleGID (v109 real role prop)
        + _v48_u64(0)             # RoleType
        + _v48_u64(clan["clan_id"] if clan else 0)  # ClanID
        + _v48_u32(0) + _v48_u32(0) + _v48_u32(0) + _v48_u32(0)
        + _v48_u16(0)
        + _v48_dt_zero() + _v48_dt_zero()
        + _v48_u32(0) + _v48_u32(0)
        + _v48_u32(1)       # Level
        + _v48_i32(0) + _v48_i32(0) + _v48_i32(0)
        + _v48_u32(0)
        + _v48_dt_zero()
        + _v48_u64(0) + _v48_u64(0)
        + _v48_i32(0) + _v48_u32(0)
        + _v48_u16(0) + _v48_u16(0)
        + _v48_i32(0) + _v48_i32(0)
        + _v48_dt_zero()
        + _v48_u16(0) + _v48_u16(0) + _v48_u16(0) + _v48_u16(0)
        + _v48_dt_zero()
        + _v48_i32(0) + _v48_u32(0)
        + _v48_u16(0) + _v48_u16(0)
        + _v48_u64(0)
        + _v48_u16(0)
        + _v48_dt_zero()
        + _v48_u32(0)
    )


def _v48_build_playerinfo(seq, uin=10001, cur_role_gid=None, nickname="LocalPlayer"):
    info = _v48_player_info(
        uin=uin,
        nickname=nickname,
        cur_role_gid=cur_role_gid,
    )
    body = _v48_u16(ZONE_ERR_SUCC) + info
    return _v62_build_server_app(TGAME_ZN_MAGIC, TGAME_ZN_NTF_PLAYERINFO, body)


def _clan_debug_hex(plain):
    # Redact credentials even for truncated application payloads. C2ZN has
    # its client sequence at +0, magic at +4, and command at +6.
    if len(plain) >= 8 and plain[4:6] == b'\x32\x43':
        cmd = struct.unpack_from('>H', plain, 6)[0]
        if cmd in CLAN_SENSITIVE_COMMANDS:
            return '<clan credentials redacted>'
    return plain.hex()


def _clan_dispatch(conn, key, app, session_uin, label):
    replies, affected = CLAN_SERVICE.handle(app['cmd'], app['body'], int(session_uin or 0))
    # Badge purchases debit SQLite directly, atomically with the grant. Refresh
    # the mall working set before any later inventory save can restore old funds.
    if app['cmd'] in (0xB04A, 0xB025) and int(session_uin or 0) in affected:
        _V140_PLAYER_STATE.reload(int(session_uin))
        if app['cmd'] == 0xB025:
            _v140_send_wallet_sync(conn, key, label, reason=0, prefix='clan expansion')
    for cmd, body in replies:
        _v48_send_app(conn, key, _v62_build_server_app(TGAME_ZN_MAGIC, cmd, body), label,
                      f'CLAN response cmd=0x{cmd:04X} uin={session_uin}')
    log('CLAN', f'cmd=0x{app["cmd"]:04X} uin={session_uin} replies={len(replies)} changed={sorted(affected)}')
    for uin in sorted(affected):
        session = _v150_session_snapshot(uin)
        if not session:
            continue
        state = PLAYER_DB.load_player_state(uin)
        info = _v48_player_info(uin=uin, nickname=PLAYER_DB.load_nickname(uin) or '', player_state=state)
        profile = _v62_build_server_app(TGAME_ZN_MAGIC, TGAME_ZN_NTF_PLAYERINFO, _v48_u16(ZONE_ERR_SUCC) + info)
        _v150_send_online(uin, profile, f'CLAN membership profile uin={uin}')
        if CLAN_DB.get_player_clan(uin):
            for update_cmd, update_body in CLAN_SERVICE.refresh_replies(uin):
                packet = _v62_build_server_app(TGAME_ZN_MAGIC, update_cmd, update_body)
                _v150_send_online(uin, packet, f'CLAN menu refresh cmd=0x{update_cmd:04X}')
        elif app['cmd'] == 0xB039:
            for update_cmd, update_body in CLAN_SERVICE.disband_replies(uin):
                packet = _v62_build_server_app(TGAME_ZN_MAGIC, update_cmd, update_body)
                _v150_send_online(uin, packet, f'CLAN disband refresh cmd=0x{update_cmd:04X}')


def _v48_build_empty_playerprops(seq):
    # ZN2C_NtfPlayerProps:
    # u16 Result | u8 IsLastPkg | i16 PropCount | PropInfo[N]
    body = _v48_u16(ZONE_ERR_SUCC) + _v48_u8(1) + _v48_i16(0)
    return _v62_build_server_app(TGAME_ZN_MAGIC, TGAME_ZN_NTF_PLAYERPROPS, body)


def _v48_build_zonehints(seq):
    return _v62_build_server_app(
        TGAME_ZN_MAGIC, TGAME_ZN_NTF_ZONE_HINTS, _v48_u16(0)
    )


def _v6_build_curr_online_time_response(seq=0, seconds=0):
    """ZN2C_ResCurrOnlineTime (0xC11A): one big-endian u32 seconds field.

    Server application responses on this transport do not include the client's
    app sequence prefix. ``seq`` is retained only for call-site/log symmetry.
    """
    return _v62_build_server_app(
        TGAME_ZN_MAGIC,
        TGAME_ZN_RES_CURR_ONLINE_TIME,
        _v48_u32(int(seconds) & 0xFFFFFFFF),
    )


def _v48_build_heartbeat_response(seq):
    return _v62_build_server_app(
        TGAME_ZN_MAGIC, TGAME_ZN_RES_HEARTBEAT, _v48_u8(0)
    )


def _v22_parse_change_login_role(body):
    """C2ZN_ReqChangeRole (A146): two big-endian u16 role indexes."""
    body = bytes(body)
    if len(body) != 4:
        raise ValueError(
            f"ChangeLoginRole (A146) must be exactly 4B, got {len(body)}B: "
            f"{body.hex()}"
        )
    return struct.unpack(">HH", body)


def _v22_build_change_login_role_response():
    """ZN2C_ResChangeRole (A147): u16 Result."""
    return _v62_build_server_app(
        TGAME_ZN_MAGIC,
        TGAME_ZN_RES_CHANGE_ROLE,
        _v48_u16(ZONE_ERR_SUCC),
    )


def _v23_parse_season_time_request(body, name):
    """F124/F126 requests are exactly one padding byte."""
    body = bytes(body or b"")
    if len(body) != 1:
        raise ValueError(
            f"{name} request must be exactly 1B, got {len(body)}B: {body.hex()}"
        )
    return body[0]


def _v26_build_season_time_response(response_cmd):
    """F125/F127 compatibility response kept identical to verified v25.

    This candidate is for first-login nickname lifecycle regression testing.
    Do not mix the separate season-time wire-format experiment into this fix.
    """
    body = _v48_u16(ZONE_ERR_SUCC) + (b"\x00" * 24)
    if len(body) != 26:
        raise AssertionError(
            f"unexpected season-time response body len={len(body)}"
        )
    return _v62_build_server_app(
        TGAME_ZN_MAGIC,
        response_cmd,
        body,
    )


def _v48_build_createaccount_response(seq, result=ZONE_ERR_SUCC):
    return _v62_build_server_app(
        TGAME_ZN_MAGIC, TGAME_ZN_RES_CREATEACCOUNT,
        _v48_u16(result)
    )


def _v5_parse_first_nickname(body):
    """Accept the two historical PH forms: TDR string or NUL C-string."""
    body = bytes(body or b"")
    if len(body) >= 5:
        n = struct.unpack_from(">I", body, 0)[0]
        if 1 <= n <= 32 and 4 + n <= len(body):
            raw = body[4:4+n]
            if raw.endswith(b"\x00"):
                raw = raw[:-1]
            return raw.decode("latin1", "strict")
    end = body.find(b"\x00")
    if end < 0:
        if len(body) > 31:
            raise ValueError("nickname missing NUL / exceeds 31 bytes")
        raw = body
    else:
        raw = body[:end]
    return raw.decode("latin1", "strict")


def _v5_validate_first_nickname(nickname):
    name = str(nickname or "")
    try:
        raw = name.encode("latin1", "strict")
    except UnicodeEncodeError:
        return False, "", "nickname is not encodable in PH single-byte field"
    if not (1 <= len(raw) <= 31):
        return False, "", f"nickname length must be 1..31 bytes (got {len(raw)})"
    if name != name.strip():
        return False, "", "nickname may not start or end with whitespace"
    if any(b < 0x20 or b == 0x7F for b in raw):
        return False, "", "nickname contains control characters"
    return True, name, "ok"


def _v26_nickname_claim_failure_result(exc: Exception) -> int:
    """Map atomic nickname-claim failures to stock PH CreateRole results."""
    if isinstance(exc, PlayerDBError):
        message = str(exc).casefold()
        if "nickname unavailable" in message:
            return ZONE_FAIL_NICKNAME_EXIST
        if "invalid nickname" in message:
            return ZONE_FAIL_ILLEGAL_NICKNAME
    return ZONE_FAIL_SERVER_BUSY


def _v5_build_check_nickname_response(result=ZONE_ERR_SUCC):
    # Prior-recovered A145 family: Result-only response.
    return _v62_build_server_app(
        TGAME_ZN_MAGIC,
        TGAME_ZN_RES_CHECK_NICKNAME,
        _v48_u16(result),
    )


def _v73_parse_main_channel_list_request(body):
    """C2ZN_ReqMainChnlList (0xA355): one big-endian u32 Padding."""
    if len(body) != 4:
        raise ValueError(
            f"MainChnlList request must be exactly 4B, got {len(body)}B"
        )
    return struct.unpack(">I", body)[0]


def _v74_build_main_channel_list_response():
    """Build one-row ZN2C_ResMainChnlList (0xA356).

    v74 corrects two wire details using the already runtime-verified v70+
    TGame behavior:

      * TDR strings on this live decoder path are encoded as
          u32_be(strlen+1) || NUL-terminated bytes
        (same form that made A005 NickName decode correctly).

      * TDR IP values that TGame later copies directly into sockaddr memory
        must be serialized numerically as 0x0100007F so the decoded little-
        endian host dword contains bytes 7F 00 00 01 == 127.0.0.1.

    Schema from proto_c2zn.tdr:
      u16 Result
      i16 MainChnlCount
      MainChnlInfo MainChnlArray[MainChnlCount]

    MainChnlInfo:
      u16 MainChnlId
      u16 MainChnlType
      string MainChnlName[32]
      u32 PlayerCapacity
      u32 PlayerNum
      ip DsaIPs[3]
    """
    main_info = (
        _v48_u16(1)
        + _v48_u16(0)  # Do not advertise MainChnl_Rookie(1); avoids the client 0-14 rookie-level gate
        + _v50_geo_tdr_string("Local Channel", 32)
        + _v48_u32(100)
        + _v48_u32(1)
        + _v48_u32(0x0100007F)
        + _v48_u32(0x0100007F)
        + _v48_u32(0x0100007F)
    )

    body = (
        _v48_u16(ZONE_ERR_SUCC)
        + _v48_i16(1)
        + main_info
    )

    # 2 Result + 2 count + 2 id + 2 type +
    # 4-byte string length + 14-byte "Local Channel\0" +
    # 4 capacity + 4 online + 12 bytes DsaIPs = 46 bytes.
    if len(body) != 46:
        raise AssertionError(
            f"unexpected ZN2C_ResMainChnlList body len={len(body)}"
        )

    return _v62_build_server_app(
        TGAME_ZN_MAGIC,
        TGAME_ZN_RES_MAINCHNLLIST,
        body,
    )



def _v159_parse_channel_ping_request(body):
    if len(body) != 4:
        raise ValueError(
            f"channel timing request must be exactly 4B, got {len(body)}B"
        )
    return struct.unpack(">I", body)[0]


def _v159_build_channel_ping_response():
    body = _v48_u16(ZONE_ERR_SUCC) + _v50_geo_tdr_string("", 256)
    return _v62_build_server_app(
        TGAME_ZN_MAGIC,
        TGAME_ZN_RES_CHANNEL_PING_VALUE,
        body,
    )


def _v75_parse_zone_channel_list_request(body):
    """C2ZN_ReqZoneChannelList (0xA132): u32 MainChannelId.

    Live capture from the client is exactly 4 bytes; for the selected local
    main channel the body is 00 00 00 01.
    """
    if len(body) != 4:
        raise ValueError(
            f"ZoneChannelList request must be exactly 4B, got {len(body)}B"
        )
    return struct.unpack(">I", body)[0]


def _v76_build_zone_channel_list_response(main_channel_id=1):
    """Build a minimal ZN2C_ResZoneChannelList (0xA133).

    The command-specific metalib shows the A133 response member as ZoneList;
    there is no leading Result field in this message.  The nested data names
    in proto_c2zn.tdr are, in order:

      ZoneChannelListInfo:
        u8  IsLastPkg
        i16 ZoneCount
        ZoneChannelInfo Zones[ZoneCount]

      ZoneChannelInfo:
        u32 MainChannelId
        ip  Ipv4
        string Domain
        u16 Port
        i32 ChannelCount
        ChannelInfo Channels[ChannelCount]
        i32 FalseChnlCount
        ChannelInfo FalseChnls[FalseChnlCount]

      ChannelInfo:
        u32 Id
        string Name
        u32 PlayerCapacity
        u32 PlayerNum
        u32 PMPlayerNum
        u32 CMPlayerNum
        u32 NMPlayerNum
        u32 RAPlayerNum

    As with the now-accepted A356 path, live TGame decoding requires the
    length-prefixed string helper and 0x0100007F for localhost IP values.
    """

    channel = (
        _v48_u32(1)                                  # Id / SubChannelId
        + _v50_geo_tdr_string("Local Subchannel", 32)
        + _v48_u32(100)                              # PlayerCapacity
        + _v48_u32(1)                                # PlayerNum
        + _v48_u32(0)                                # PMPlayerNum
        + _v48_u32(0)                                # CMPlayerNum
        + _v48_u32(1)                                # NMPlayerNum (normal)
        + _v48_u32(0)                                # RAPlayerNum
    )

    zone = (
        _v48_u32(main_channel_id)
        + _v48_u32(0x0100007F)                       # 127.0.0.1 in TGame host-memory form
        + _v50_geo_tdr_string("127.0.0.1", 128)
        + _v48_u16(TGAME_ZONE_PORT)
        + _v48_i32(1)                                # ChannelCount (schema: 4 bytes)
        + channel
        + _v48_i32(0)                                # FalseChnlCount (schema: 4 bytes)
    )

    body = (
        _v48_u8(1)                                   # IsLastPkg
        + _v48_i16(1)                                # ZoneCount
        + zone
    )

    # Wire body is 84 bytes for this one-zone/one-channel response.
    # v75 incorrectly used 16-bit ChannelCount/FalseChnlCount and produced 80B,
    # shifting every field after Port by 2 bytes at each count.
    if len(body) != 84:
        raise AssertionError(f"unexpected A133 body len={len(body)}")

    return _v62_build_server_app(
        TGAME_ZN_MAGIC,
        TGAME_ZN_RES_ZONECHANNEL_LIST,
        body,
    )


def _v77_parse_match_room_list_request(body):
    """Decode C2ZN_ReqMatchRoomList (0xA100).

    proto_c2zn.tdr defines:
      MatchRoomFilterInfo:
        u32 ModeId
        u16 MapId
        u16 Flags
        u8  AtLeastCount
      u16 StartIndex
      u16 RoomCount

    Total wire size is therefore 13 bytes.  The live request observed after
    entering Local Subchannel is:
      00000000 0000 0000 00 0000 0014
    meaning all-room filter, start=0, request up to 20 rooms.
    """
    if len(body) != 13:
        raise ValueError(
            f"MatchRoomList request must be exactly 13B, got {len(body)}B"
        )
    return {
        "mode_id": struct.unpack_from(">I", body, 0)[0],
        "map_id": struct.unpack_from(">H", body, 4)[0],
        "flags": struct.unpack_from(">H", body, 6)[0],
        "at_least_count": body[8],
        "start_index": struct.unpack_from(">H", body, 9)[0],
        "room_count": struct.unpack_from(">H", body, 11)[0],
    }


def _v77_build_empty_match_room_list_response():
    """Build ZN2C_ResMatchRoomList (0xA102) with an accepted empty list.

    proto_c2zn.tdr defines:
      u16 Result
      u16 TotalRoomNum
      u16 RoomCount
      MatchRoomInfo RoomInfos[RoomCount]

    Empty lobby => Result=0x8100, TotalRoomNum=0, RoomCount=0.
    """
    body = (
        _v48_u16(ZONE_ERR_SUCC)
        + _v48_u16(0)
        + _v48_u16(0)
    )
    if len(body) != 6:
        raise AssertionError(f"unexpected A102 body len={len(body)}")
    return _v62_build_server_app(
        TGAME_ZN_MAGIC,
        TGAME_ZN_RES_MATCHROOMLIST,
        body,
    )


def _v138_build_res_leave_match_room(leave_reason=0, error_desc=""):
    """Build ZN2C_ResLeaveMatchRoom (A108) using the stock PH callback schema.

    The shipped UTGame.u proves TGOnlineMultiGameRoom exposes:
        OnTGOnlineDelegate_LeaveRoom(
            int ErrorCode,
            int LeaveReason,
            string ErrorDesc
        )

    The live A107 request carries LeaveReason as a 2-byte field.  Zone Result
    values in this command family are u16, and GEO/TDR strings use the normal
    u32 length + NUL-terminated bytes encoding already used elsewhere here.

    Body:
        u16 Result          = 0x8100
        u16 LeaveReason     = request value, normal leave = 0
        TDR string ErrorDesc = empty on success
    """
    body = (
        _v48_u16(ZONE_ERR_SUCC)
        + _v48_u16(int(leave_reason) & 0xFFFF)
        + _v50_geo_tdr_string(error_desc, 256)
    )
    return _v62_build_server_app(
        TGAME_ZN_MAGIC,
        TGAME_ZN_RES_LEAVEMATCHROOM,
        body,
    )


def _v138_build_ntf_leave_match_room(seat_index=0, leave_reason=0):
    """Build ZN2C_NtfLeaveMatchRoom (A109) using the stock PH callback schema.

    The shipped UTGame.u proves:
        OnTGOnlineDelegate_NotifyLeaveRoom(
            byte PlayerSeatIndex,
            int LeaveReason
        )

    Adjacent live-verified room notifications serialize seat indexes as u16,
    and the A107 LeaveReason itself is observed as a 2-byte field.

    Body:
        u16 PlayerSeatIndex
        u16 LeaveReason
    """
    body = (
        _v48_u16(int(seat_index) & 0xFFFF)
        + _v48_u16(int(leave_reason) & 0xFFFF)
    )
    return _v62_build_server_app(
        TGAME_ZN_MAGIC,
        TGAME_ZN_NTF_LEAVEMATCHROOM,
        body,
    )


def _v143b_build_res_quit_match():
    """Build the observed successful A118 QuitMatch response (Result:u16)."""
    return _v62_build_server_app(
        TGAME_ZN_MAGIC,
        TGAME_ZN_RES_QUITMATCH,
        _v48_u16(ZONE_ERR_SUCC),
    )


def _v143b_build_ntf_quit_match(seat_index=0):
    """Build ZN2C_NtfQuitMatch (A119): u16 PlayerSeatIndex."""
    return _v62_build_server_app(
        TGAME_ZN_MAGIC,
        TGAME_ZN_NTF_QUITMATCH,
        _v48_u16(int(seat_index) & 0xFFFF),
    )


def _v78_build_create_match_room_response(result=ZONE_ERR_SUCC):
    """Build ZN2C_ResCreateMatchRoom (0xA10B).

    proto_c2zn.tdr defines this response as a single u16 Result field.
    """
    body = _v48_u16(int(result) & 0xFFFF)
    if len(body) != 2:
        raise AssertionError(f"unexpected A10B body len={len(body)}")
    return _v62_build_server_app(
        TGAME_ZN_MAGIC,
        TGAME_ZN_RES_CREATEMATCHROOM,
        body,
    )


def _v82_match_room_player_info(uin=10001, nickname="LocalPlayer", seat_index=0):
    """Serialize one MatchRoomPlayerInfo for A105/A106.

    proto_c2zn.tdr field order:
      u64 Uin
      string NickName[32]
      u32 State
      u16 Flags
      u16 SeatIndex
      u32 SpecEquipFlags
    """
    return (
        _v48_u64(uin)
        + _v50_geo_tdr_string(nickname, 32)
        + _v48_u32(8)      # EPlayerState_Unready
        + _v48_u16(4)      # EPlayerFlag_RoomOwner
        + _v48_u16(seat_index)
        + _v48_u32(0)      # SpecEquipFlags
    )


def _v82_build_res_enter_match_room(room, uin=10001, nickname="LocalPlayer"):
    """Build ZN2C_ResEnterMatchRoom (0xA105) with complete room state.

    Raw proto_c2zn.tdr places these fields in MatchRoomInfo, in order:
      u64 RoomId
      u16 DisplayeId
      u64 QQTalkRoomId
      u32 SubChannelId
      string Name[64]
      MatchSettings
      u8 FighterCapacity
      u8 ObserverCapacity
      u8 FighterCount
      u8 ObserverCount
      u16 PlayerCount
      MatchRoomPlayerInfo PlayerInfos[PlayerCount]

    v81 proved that A106 by itself does not transition the creator.  A105 is
    the creator/enter response and carries the complete MatchRoomInfo needed
    to establish the local room state.
    """
    player = _v82_match_room_player_info(
        uin=uin,
        nickname=nickname,
        seat_index=0,
    )

    room_info = (
        _v48_u64(room["room_id"])
        + _v48_u16(room["display_id"])
        + _v48_u64(room.get("qqtalk_room_id", 0))
        + _v48_u32(room.get("sub_channel_id", 1))
        + _v50_geo_tdr_string(room["name"], 64)
        + room["match_settings_wire"]
        + _v48_u8(room["fighter_capacity"])
        + _v48_u8(room["observer_capacity"])
        + _v48_u8(room.get("fighter_count", 1))
        + _v48_u8(room.get("observer_count", 0))
        + _v48_u8(1)       # PlayerCount -- proto_c2zn.tdr: uint8
        + player
    )

    body = _v48_u16(ZONE_ERR_SUCC) + room_info
    return _v62_build_server_app(
        TGAME_ZN_MAGIC,
        TGAME_ZN_RES_ENTERMATCHROOM,
        body,
    )


def _v81_build_ntf_enter_match_room(uin=10001, nickname="LocalPlayer", seat_index=0):
    """Build ZN2C_NtfEnterMatchRoom (0xA106) for the room creator.

    proto_c2zn.tdr defines ZN2C_NtfEnterMatchRoom as exactly one
    MatchRoomPlayerInfo:
      u64 Uin
      string NickName[32]
      u32 State
      u16 Flags
      u16 SeatIndex
      u32 SpecEquipFlags

    Runtime enum values recovered from the same metalib:
      EPlayerState_Unready = 8
      EPlayerFlag_RoomOwner = 4
    """
    body = (
        _v48_u64(uin)
        + _v50_geo_tdr_string(nickname, 32)
        + _v48_u32(8)      # EPlayerState_Unready
        + _v48_u16(4)      # EPlayerFlag_RoomOwner
        + _v48_u16(seat_index)
        + _v48_u32(0)      # SpecEquipFlags
    )
    return _v62_build_server_app(
        TGAME_ZN_MAGIC,
        TGAME_ZN_NTF_ENTERMATCHROOM,
        body,
    )



def _v150_pack_match_room_player_info(member):
    return (
        _v48_u64(int(member["uin"]))
        + _v50_geo_tdr_string(str(member.get("nickname") or f"Player{int(member['uin'])}")[:31], 32)
        + _v48_u32(int(member.get("state", 8)))
        + _v48_u16(int(member.get("flags", 0)))
        + _v48_u16(int(member.get("seat_index", 0)))
        + _v48_u32(int(member.get("spec_equip_flags", 0)))
    )


def _v150_build_res_enter_match_room(room):
    """A105 full MatchRoomInfo for creator OR a later A104 joiner."""
    members = sorted(
        list(room.get("members") or []),
        key=lambda m: (int(m.get("seat_index", 0)), int(m.get("uin", 0))),
    )
    if len(members) > 0xFF:
        raise ValueError("MatchRoomInfo.PlayerCount exceeds uint8")
    room_info = (
        _v48_u64(room["room_id"])
        + _v48_u16(room["display_id"])
        + _v48_u64(room.get("qqtalk_room_id", 0))
        + _v48_u32(room.get("sub_channel_id", 1))
        + _v50_geo_tdr_string(room["name"], 64)
        + room["match_settings_wire"]
        + _v48_u8(room["fighter_capacity"])
        + _v48_u8(room["observer_capacity"])
        + _v48_u8(room.get("fighter_count", 0))
        + _v48_u8(room.get("observer_count", 0))
        + _v48_u8(len(members))
        + b"".join(_v150_pack_match_room_player_info(m) for m in members)
    )
    return _v62_build_server_app(
        TGAME_ZN_MAGIC,
        TGAME_ZN_RES_ENTERMATCHROOM,
        _v48_u16(ZONE_ERR_SUCC) + room_info,
    )


def _v150_build_ntf_enter_match_room(member):
    return _v62_build_server_app(
        TGAME_ZN_MAGIC,
        TGAME_ZN_NTF_ENTERMATCHROOM,
        _v150_pack_match_room_player_info(member),
    )


def _v150_parse_enter_match_room(body):
    """Tolerant live A103 decoder: required u64 RoomId, optional TDR password/tail."""
    if len(body) < 8:
        raise ValueError(f"A103 too short: {len(body)}B")
    room_id = struct.unpack_from(">Q", body, 0)[0]
    off = 8
    password = ""
    observer = False
    if off < len(body):
        try:
            password, _raw, off = _v79_read_lp_string(body, off, 8)
        except Exception:
            off = 8
        if off < len(body) and len(body) - off == 1:
            observer = bool(body[off])
            off += 1
    return {
        "room_id": int(room_id),
        "password": password,
        "observer": observer,
        "tail": bytes(body[off:]),
    }


def _r15_a103_enter_request_selftest():
    live_body = bytes.fromhex("0000000000000001000000010000")
    parsed = _v150_parse_enter_match_room(live_body)
    if parsed != {
        "room_id": 1,
        "password": "",
        "observer": False,
        "tail": b"",
    }:
        raise AssertionError(f"r15 A103 parser mismatch: {parsed!r}")
    if TGAME_ZN_REQ_ENTERMATCHROOM != 0xA103:
        raise AssertionError(
            f"r15 EnterRoomByRoomId command drifted: 0x{TGAME_ZN_REQ_ENTERMATCHROOM:04X}"
        )
    return True


R14_A102_ENTERABILITY_FLAG = 0x00004000

# v5.6 VERIFIED from a same-room PH 1.0.0.24 capture:
#   room creation / No Late Join OFF: flags=0x00003808
#   after ticking stock "No Late Join": flags=0x00003800
#
# Therefore bit 0x00000008 is an ALLOW-LATE-JOIN bit.  The stock checkbox
# "No Late Join" clears this bit.  Do not invert this again.
TGAME_LATE_JOIN_ALLOWED_FLAG = 0x00000008

def _v150_no_late_join_from_flags(flags):
    return not bool(int(flags) & TGAME_LATE_JOIN_ALLOWED_FLAG)


def _v56_no_late_join_flag_selftest():
    assert _v150_no_late_join_from_flags(0x00003808) is False
    assert _v150_no_late_join_from_flags(0x00003800) is True
    return True


_V56_NO_LATE_JOIN_FLAG_SELFTEST = _v56_no_late_join_flag_selftest()


def _r14_a102_match_settings_wire(room):
    original_wire = bytes(room["match_settings_wire"])
    if len(original_wire) < 18:
        raise ValueError(
            f"r14 A102 MatchSettings too short: {len(original_wire)}B"
        )
    map_string_len = struct.unpack_from(">I", original_wire, 6)[0]
    flags_off = 14 + int(map_string_len)
    if map_string_len < 1 or flags_off + 4 > len(original_wire):
        raise ValueError("r14 A102 invalid MatchSettings MapString/flags layout")
    wire_flags = struct.unpack_from(">I", original_wire, flags_off)[0]
    canonical_flags = int(room.get("flags", wire_flags)) & 0xFFFFFFFF
    if wire_flags != canonical_flags:
        raise ValueError("r14 A102 preserved flags differ from canonical room flags")
    projected = bytearray(original_wire)
    struct.pack_into(
        ">I", projected, flags_off,
        wire_flags | R14_A102_ENTERABILITY_FLAG,
    )
    return bytes(projected)


def _r14_a102_projection_selftest():
    raw = (
        struct.pack(">IH", 0x00002001, 0x002F)
        + struct.pack(">I", 1)
        + b"\x00"
        + struct.pack(">II", 0x00001001, 0x00003008)
    )
    room = {"match_settings_wire": raw, "flags": 0x00003008}
    projected = _r14_a102_match_settings_wire(room)
    return (
        raw != projected
        and struct.unpack_from(">I", projected, 15)[0] == 0x00007008
        and room["match_settings_wire"] == raw
    )


_R14_A102_PROJECTION_SELFTEST = _r14_a102_projection_selftest()


def _v150_pack_basic_match_room_info(room):
    return (
        _v48_u64(room["room_id"])
        + _v48_u16(room["display_id"])
        + _v48_u64(room.get("qqtalk_room_id", 0))
        + _v50_geo_tdr_string(room["name"], 64)
        + _v50_geo_tdr_string(room.get("owner_name", "LocalPlayer"), 32)
        + _r14_a102_match_settings_wire(room)
        + _v48_u8(room["fighter_capacity"])
        + _v48_u8(room["observer_capacity"])
        + _v48_u8(room.get("fighter_count", 0))
        + _v48_u8(room.get("observer_count", 0))
    )


def _v150_filter_match_rooms(req, rooms):
    filtered = []
    for room in rooms:
        if room.get("started") and room.get("no_late_join"):
            continue
        if int(req.get("mode_id", 0)) not in (0, int(room.get("mode_id", 0))):
            continue
        if int(req.get("map_id", 0)) not in (0, int(room.get("map_id", 0))):
            continue
        filtered.append(room)
    filtered.sort(key=lambda r: (int(r.get("display_id", 0)), int(r["room_id"])))
    total = len(filtered)
    start = min(max(0, int(req.get("start_index", 0))), total)
    want = int(req.get("room_count", 0)) or 20
    want = max(1, min(want, 20))
    return total, filtered[start:start + want]


# r17: second u16 is FIRST/LAST page flags, not TotalRoomNum.
R17_A102_PAGEFLAGS_FIRST = 0x0001
R17_A102_PAGEFLAGS_LAST = 0x0002
R17_A102_PAGEFLAGS_SINGLE = (
    R17_A102_PAGEFLAGS_FIRST | R17_A102_PAGEFLAGS_LAST
)


def _v150_build_match_room_list_response(total_room_num, rooms):
    rows = list(rooms)
    body = (
        _v48_u16(ZONE_ERR_SUCC)
        + _v48_u16(R17_A102_PAGEFLAGS_SINGLE)
        + _v48_u16(len(rows) & 0xFFFF)
        + b"".join(_v150_pack_basic_match_room_info(r) for r in rows)
    )
    return _v62_build_server_app(
        TGAME_ZN_MAGIC,
        TGAME_ZN_RES_MATCHROOMLIST,
        body,
    )


def _r17_a102_prefix_selftest():
    one_row_prefix = (
        _v48_u16(ZONE_ERR_SUCC)
        + _v48_u16(R17_A102_PAGEFLAGS_SINGLE)
        + _v48_u16(1)
    )
    empty_prefix = (
        _v48_u16(ZONE_ERR_SUCC)
        + _v48_u16(R17_A102_PAGEFLAGS_SINGLE)
        + _v48_u16(0)
    )
    if one_row_prefix.hex() != "810000030001":
        raise AssertionError(
            f"r17 A102 one-row prefix mismatch: {one_row_prefix.hex()}"
        )
    if empty_prefix.hex() != "810000030000":
        raise AssertionError(
            f"r17 A102 empty prefix mismatch: {empty_prefix.hex()}"
        )
    return True


_R17_A102_PREFIX_SELFTEST = _r17_a102_prefix_selftest()


R20_UI_SEAT_SLOTS = 32
R20_CAMP_SPAN = 16


def _r20_map_pve_camp_seat(old_seat, requested_camp, fighter_capacity):
    old_seat = int(old_seat)
    requested_camp = int(requested_camp)
    fighter_capacity = int(fighter_capacity)
    if requested_camp not in (0, 1):
        raise ValueError(f"invalid camp {requested_camp}")
    if (
        fighter_capacity < 2
        or fighter_capacity > 16
        or fighter_capacity % 2
    ):
        raise ValueError(
            f"unsupported With32 fighter_capacity {fighter_capacity}; "
            "expected an even value from 2 through 16"
        )
    if old_seat < 0 or old_seat >= R20_UI_SEAT_SLOTS:
        raise ValueError(f"old seat out of 32-seat UI range: {old_seat}")
    row = old_seat % R20_CAMP_SPAN
    visible_rows = fighter_capacity // 2
    if row >= visible_rows:
        raise ValueError(
            f"seat row {row} outside active rows 0..{visible_rows - 1}"
        )
    return (R20_CAMP_SPAN if requested_camp == 0 else 0) + row


def _r20_sparse_seat_mapping_selftest():
    # 4-player layout: 0/1 <-> 16/17.
    assert _r20_map_pve_camp_seat(0, 0, 4) == 16
    assert _r20_map_pve_camp_seat(1, 0, 4) == 17
    assert _r20_map_pve_camp_seat(16, 1, 4) == 0
    assert _r20_map_pve_camp_seat(17, 1, 4) == 1

    # 6-player layout: 0/1/2 <-> 16/17/18.
    assert _r20_map_pve_camp_seat(0, 0, 6) == 16
    assert _r20_map_pve_camp_seat(2, 0, 6) == 18
    assert _r20_map_pve_camp_seat(18, 1, 6) == 2

    # 16-player layout: 0..7 <-> 16..23.
    assert _r20_map_pve_camp_seat(7, 0, 16) == 23
    assert _r20_map_pve_camp_seat(23, 1, 16) == 7
    return True


_R20_SPARSE_SEAT_MAPPING_SELFTEST = _r20_sparse_seat_mapping_selftest()


def _v79_read_lp_string(body, off, max_wire_len=None):
    if off + 4 > len(body):
        raise ValueError("truncated length-prefixed string length")
    n = struct.unpack_from(">I", body, off)[0]
    off += 4
    if n < 1 or off + n > len(body):
        raise ValueError(
            f"invalid length-prefixed string n={n} off={off} body={len(body)}"
        )
    if max_wire_len is not None and n > max_wire_len:
        raise ValueError(f"string n={n} exceeds max {max_wire_len}")
    raw = body[off:off+n]
    off += n
    text_raw = raw[:-1] if raw.endswith(b"\x00") else raw
    return text_raw.decode("latin1", "replace"), raw, off


_R15_A103_ENTER_SELFTEST = _r15_a103_enter_request_selftest()


def _v143b_parse_set_game_settings_request(body):
    """Parse live A11E TGOnlineMultiGameRoom.SetGameSettings MatchSettings.

    Verified PH wire order:
      u32 ModeId
      u16 MapId
      string MapString[32]
      u32 SubModeId
      u32 Flags
      u16 SettingType
      u16 Value
      u16 RespawnTime
      u16 RecodeType
      u16 LiveDelaySec

    No response packet is fabricated: the verified client flow sends A11E and
    then proceeds to A113 StartMatch after the authoritative room state changes.
    """
    off = 0
    if off + 6 > len(body):
        raise ValueError("A11E truncated MatchSettings prefix")
    mode_id = struct.unpack_from(">I", body, off)[0]; off += 4
    map_id = struct.unpack_from(">H", body, off)[0]; off += 2
    map_string, _map_raw, off = _v79_read_lp_string(body, off, 32)
    if off + 18 > len(body):
        raise ValueError("A11E truncated MatchSettings tail")
    sub_mode_id = struct.unpack_from(">I", body, off)[0]; off += 4
    flags = struct.unpack_from(">I", body, off)[0]; off += 4
    setting_type = struct.unpack_from(">H", body, off)[0]; off += 2
    value = struct.unpack_from(">H", body, off)[0]; off += 2
    respawn_time = struct.unpack_from(">H", body, off)[0]; off += 2
    recode_type = struct.unpack_from(">H", body, off)[0]; off += 2
    live_delay_sec = struct.unpack_from(">H", body, off)[0]; off += 2
    return {
        "mode_id": mode_id,
        "map_id": map_id,
        "map_string": map_string,
        "sub_mode_id": sub_mode_id,
        "flags": flags,
        "setting_type": setting_type,
        "value": value,
        "respawn_time": respawn_time,
        "recode_type": recode_type,
        "live_delay_sec": live_delay_sec,
        "match_settings_wire": bytes(body[:off]),
        "tail": bytes(body[off:]),
    }


def _v79_parse_create_match_room_request(body):
    """Parse the fields needed to mirror a newly-created room in A102.

    C2ZN_ReqCreateMatchRoom:
      string Name[64]
      MatchSettings
      u8 FighterCapacity
      u8 ObserverCapacity
      string Password[8]
      GameServerInfo

    MatchSettings is variable on the wire only because MapString is a TDR
    string.  We preserve its exact wire bytes from the accepted client request
    instead of re-encoding mode-specific fields.
    """
    off = 0
    name, _name_raw, off = _v79_read_lp_string(body, off, 64)

    ms_start = off
    if off + 6 > len(body):
        raise ValueError("truncated MatchSettings prefix")
    mode_id = struct.unpack_from(">I", body, off)[0]; off += 4
    map_id = struct.unpack_from(">H", body, off)[0]; off += 2
    map_string, _map_raw, off = _v79_read_lp_string(body, off, 32)
    if off + 18 > len(body):
        raise ValueError("truncated MatchSettings tail")
    sub_mode_id = struct.unpack_from(">I", body, off)[0]; off += 4
    flags = struct.unpack_from(">I", body, off)[0]; off += 4
    setting_type = struct.unpack_from(">H", body, off)[0]; off += 2
    value = struct.unpack_from(">H", body, off)[0]; off += 2
    respawn_time = struct.unpack_from(">H", body, off)[0]; off += 2
    recode_type = struct.unpack_from(">H", body, off)[0]; off += 2
    live_delay_sec = struct.unpack_from(">H", body, off)[0]; off += 2
    ms_end = off

    if off + 2 > len(body):
        raise ValueError("truncated room capacities")
    fighter_capacity = body[off]
    observer_capacity = body[off+1]
    off += 2

    password, _pw_raw, off = _v79_read_lp_string(body, off, 8)
    game_server_info = body[off:]

    return {
        "name": name,
        "mode_id": mode_id,
        "map_id": map_id,
        "map_string": map_string,
        "sub_mode_id": sub_mode_id,
        "flags": flags,
        "setting_type": setting_type,
        "value": value,
        "respawn_time": respawn_time,
        "recode_type": recode_type,
        "live_delay_sec": live_delay_sec,
        "match_settings_wire": body[ms_start:ms_end],
        "fighter_capacity": fighter_capacity,
        "observer_capacity": observer_capacity,
        "password": password,
        "game_server_info": game_server_info,
    }


def _v79_build_match_room_list_response(room=None):
    """Build ZN2C_ResMatchRoomList (0xA102), optionally with one room.

    BasicMatchRoomInfo from proto_c2zn.tdr:
      u64 Id
      u16 DisplayeId
      u64 QQTalkRoomId
      string Name[64]
      string OwnerName[32]
      MatchSettings
      u8 FighterCapacity
      u8 ObserverCapacity
      u8 FighterCount
      u8 ObserverCount
    """
    if room is None:
        body = (
            _v48_u16(ZONE_ERR_SUCC)
            + _v48_u16(0)
            + _v48_u16(0)
        )
    else:
        info = (
            _v48_u64(room["room_id"])
            + _v48_u16(room["display_id"])
            + _v48_u64(room.get("qqtalk_room_id", 0))
            + _v50_geo_tdr_string(room["name"], 64)
            + _v50_geo_tdr_string(room.get("owner_name", "LocalPlayer"), 32)
            + room["match_settings_wire"]
            + _v48_u8(room["fighter_capacity"])
            + _v48_u8(room["observer_capacity"])
            + _v48_u8(room.get("fighter_count", 1))
            + _v48_u8(room.get("observer_count", 0))
        )
        body = (
            _v48_u16(ZONE_ERR_SUCC)
            + _v48_u16(1)
            + _v48_u16(1)
            + info
        )

    return _v62_build_server_app(
        TGAME_ZN_MAGIC,
        TGAME_ZN_RES_MATCHROOMLIST,
        body,
    )


def _v77_peek_create_match_room_request(body):
    """Best-effort peek at the front of C2ZN_ReqCreateMatchRoom (0xA10A).

    The complete schema is Name + MatchSettings + capacities + Password +
    GameServerInfo.  For the first live capture we intentionally do not guess
    the tail; this helper only extracts the leading length-prefixed room name
    when present and leaves the full request available in the log.
    """
    info = {"body_len": len(body), "room_name": None}
    if len(body) >= 4:
        n = struct.unpack_from(">I", body, 0)[0]
        if 1 <= n <= 64 and 4 + n <= len(body):
            raw = body[4:4+n]
            if raw.endswith(b"\x00"):
                raw = raw[:-1]
            info["room_name"] = raw.decode("latin1", "replace")
    return info


def _v88_build_res_change_match_room_camp():
    """ZN2C_ResChangeMatchRoomCamp (0xA10E): u16 Result."""
    return _v62_build_server_app(
        TGAME_ZN_MAGIC,
        TGAME_ZN_RES_CHANGEMATCHROOMCAMP,
        _v48_u16(ZONE_ERR_SUCC),
    )


def _v88_build_ntf_change_match_room_camp(old_seat, new_seat):
    """ZN2C_NtfChangeMatchRoomCamp (0xA10F).

    proto_c2zn.tdr fields:
      u16 OldSeatIndex
      u16 NewSeatIndex
    """
    body = _v48_u16(old_seat) + _v48_u16(new_seat)
    return _v62_build_server_app(
        TGAME_ZN_MAGIC,
        TGAME_ZN_NTF_CHANGEMATCHROOMCAMP,
        body,
    )


def _v86_build_res_start_match():
    """Build ZN2C_ResStartMatch (0xA114): u16 Result."""
    body = _v48_u16(ZONE_ERR_SUCC)
    return _v62_build_server_app(
        TGAME_ZN_MAGIC,
        TGAME_ZN_RES_STARTMATCH,
        body,
    )



def _v108_build_ntf_set_in_match(seat_index=0):
    """Build ZN2C_NtfSetInMatch (inferred cmd 0xA11D).

    Static TGame handler proof:
      HandleMessage_Notification_SetInMatch reads the first payload field
      as a signed/unsigned 16-bit seat index and uses it to locate the
      MatchRoomPlayerInfo before switching that player's room state to 0x0C.

    Therefore the minimal notification body is exactly:
      u16 SeatIndex
    """
    body = _v48_u16(seat_index)
    return _v62_build_server_app(
        TGAME_ZN_MAGIC,
        TGAME_ZN_NTF_SETINMATCH,
        body,
    )


def _v87_build_game_server_info(
    # IMPORTANT: TGame's decoded IPv4 path for these server->client TDR
    # structures expects localhost serialized as 01 00 00 7F on the wire.
    # This is the same runtime-proven encoding used by the accepted A356/A133
    # channel endpoints.  v87/v88 incorrectly sent 7F 00 00 01 here.
    ip=0x0100007F,
    port=TGAME_REAL_DS_PORT,
    ds_key=TGAME_DS_KEY,
    domain="",
    is_use_domain=0,
):
    """Build GameServerInfo / DSInfo for ZN2C_NtfStartMatch.

    Recovered from proto_c2zn.tdr and validated against the 28-byte
    GameServerInfo tail TGame sends in C2ZN_ReqCreateMatchRoom:

      u32 Ip
      u16 Port
      byte DSKey[16]
      string Domain
      u8 IsUseDomain

    Example live client tail decoded as:
      Ip          = 0xffffffff
      Port        = 7777
      DSKey       = 16 bytes
      Domain      = ""
      IsUseDomain = 0

    Localhost note:
      send wire bytes 01 00 00 7F, not 7F 00 00 01.
      The latter was the v87/v88 bug.
    """
    ds_key = bytes(ds_key)
    if len(ds_key) != 16:
        raise ValueError(
            f"GameServerInfo DSKey must be exactly 16B, got {len(ds_key)}"
        )

    info = (
        _v48_u32(ip)
        + _v48_u16(port)
        + ds_key
        + _v50_geo_tdr_string(domain, 128)
        + _v48_u8(is_use_domain)
    )

    # Empty Domain serializes as u32(1) + NUL, so the local form is 28B.
    if domain == "" and len(info) != 28:
        raise AssertionError(
            f"unexpected GameServerInfo len={len(info)}, expected 28"
        )
    return info


def _v87_build_ntf_start_match(
    port=None, ds_key=None, ip=0x0100007F, domain="", is_use_domain=0
):
    """Build ZN2C_NtfStartMatch (0xA11A).

    Schema:
      u16 Result
      GameServerInfo DSInfo

    v132 allows the already-proven A11A serializer to advertise the real
    AFDEV listen server (UDP 7777) for PVE without changing the legacy 65008
    bridge path used by older experiments.
    """
    if port is None:
        port = TGAME_REAL_DS_PORT
    if ds_key is None:
        ds_key = TGAME_DS_KEY
    body = (
        _v48_u16(ZONE_ERR_SUCC)
        + _v87_build_game_server_info(
            ip=int(ip),
            port=int(port),
            ds_key=bytes(ds_key),
            domain=str(domain),
            is_use_domain=int(is_use_domain),
        )
    )
    return _v62_build_server_app(
        TGAME_ZN_MAGIC,
        TGAME_ZN_NTF_STARTMATCH,
        body,
    )


def _v132_room_mode(role_state, explicit_mode=None):
    if explicit_mode is not None:
        try:
            return int(explicit_mode)
        except Exception:
            pass
    room = role_state.get("v79_created_match_room") or {}
    try:
        return int(room.get("mode_id", 0))
    except Exception:
        return 0


def _v132_build_res_ready():
    """Minimal success ACK for C2ZN_ReqSetMatchRoomReady (A110)."""
    return _v62_build_server_app(
        TGAME_ZN_MAGIC,
        TGAME_ZN_RES_SETMATCHROOMREADY,
        _v48_u16(ZONE_ERR_SUCC),
    )


def _v134_build_ntf_set_match_room_ready(
    seat_index=0,
    ready_state=TGAME_PLAYERSTATE_READYTOMATCH,
):
    """Build the live-working ZN2C_NtfSetMatchRoomReady (A112).

    PH 1.0.0.24 two-client runtime result:
        Body = u16 SeatIndex | u32 ReadyState

    For normal fighter Ready:
        ReadyState = 9 (EPlayerState_ReadyToMatch)

    Example seat 1:
        00 01 00 00 00 09
    """
    ready_state = int(ready_state)
    if ready_state not in (
        TGAME_PLAYERSTATE_UNREADY,
        TGAME_PLAYERSTATE_READYTOMATCH,
    ):
        raise ValueError(
            f"latejoin-v2 A112 supports Unready=8/ReadyToMatch=9, got {ready_state}"
        )

    body = (
        _v48_u16(int(seat_index) & 0xFFFF)
        + _v48_u32(ready_state)
    )
    if len(body) != 6:
        raise AssertionError(
            f"r25-main A112 body len={len(body)}, expected 6"
        )

    return _v62_build_server_app(
        TGAME_ZN_MAGIC,
        TGAME_ZN_NTF_SETMATCHROOMREADY,
        body,
    )


def _v132_send_pve_afdev_handoff(
    conn,
    active_tgame_key,
    label,
    role_state,
    *,
    reason,
    room=None,
    start_settings=None,
    mode_id=None,
):
    """Send A11A once using this room's stable-v143b DS allocation.

    r10 lazy-latch + v72 zero-DSKey + multiplayer-safe cleanup flow: A10A reserves a slot only. A3A0/A113 starts and binds the
    lightweight UDP bridge, then advertises it immediately. TGame's first valid
    DS datagram to that bridge is what starts the v48 AFDEV loader.
    """
    room_for_handoff = (
        room
        if isinstance(room, dict)
        else role_state.get("v79_created_match_room") or {}
    )
    room_id = room_for_handoff.get("room_id") or role_state.get(
        "v143b_ds_room_id"
    )
    use_client_map = os.environ.get("AF_DS_USE_CLIENT_MAP", "1").strip().lower() in (
        "1", "true", "yes", "on"
    )
    map_override = None if use_client_map else V143B_DS_CONFIG.default_map or None

    requested_settings = None
    if isinstance(start_settings, dict):
        requested_settings = {
            "mode_id": start_settings.get("mode_id"),
            "match_map_id": start_settings.get("match_map_id"),
            "sub_mode_id": start_settings.get("sub_mode_id"),
            "room_flags": start_settings.get("room_flags"),
            "map_name": map_override,
        }
    elif room_for_handoff.get("room_id") is not None:
        room_map_name = (
            str(room_for_handoff.get("map_string") or "").strip()
            if use_client_map
            else ""
        )
        requested_settings = {
            "mode_id": room_for_handoff.get("mode_id"),
            "match_map_id": room_for_handoff.get("map_id"),
            "sub_mode_id": room_for_handoff.get("sub_mode_id"),
            "room_flags": room_for_handoff.get("flags"),
            "map_name": room_map_name or map_override,
        }

    if mode_id is None and isinstance(requested_settings, dict):
        mode_id = requested_settings.get("mode_id")
    mode_now = _v132_room_mode(role_state, mode_id)
    if not TGAME_PVE_DIRECT_AFDEV or mode_now not in TGAME_AFDEV_MODE_IDS:
        return False

    if role_state.get("v132_pve_afdev_handoff_sent"):
        endpoint = role_state.get(
            "v143b_ds_endpoint", f"127.0.0.1:{TGAME_AFDEV_PORT}"
        )
        log(
            "DS-HANDOFF",
            f"stable-v143b duplicate PVE A11A suppressed reason={reason} "
            f"mode=0x{mode_now:08x} endpoint={endpoint}",
        )
        return True

    handoff_host = "127.0.0.1"
    handoff_port = TGAME_AFDEV_PORT
    allocation = None

    if (
        isinstance(room_for_handoff, dict)
        and room_for_handoff.get("room_id") is not None
    ):
        role_state["v79_created_match_room"] = room_for_handoff
        role_state["v143b_ds_room_id"] = int(room_for_handoff["room_id"])

    if V143B_DS_CONFIG.enabled:
        if isinstance(requested_settings, dict):
            try:
                allocation = V143B_DS_SPAWNER.prepare_lobby_for_match(
                    owner_id=int(role_state.get("uin") or 10001),
                    owner_nickname=_v150_role_nickname(role_state),
                    room_id=(int(room_id) if room_id is not None else None),
                    max_players=max(
                        2,
                        int(room_for_handoff.get("fighter_capacity") or 0),
                    ),
                    mode_id=int(requested_settings["mode_id"]),
                    map_id=int(requested_settings["match_map_id"]),
                    sub_mode_id=int(requested_settings["sub_mode_id"]),
                    room_flags=int(requested_settings["room_flags"]),
                    map_name=requested_settings.get("map_name"),
                )
                room_id = allocation.room_id
                role_state["v143b_ds_room_id"] = int(room_id)
                log(
                    "DS-HANDOFF",
                    f"match handoff prepared DS room={room_id} reason={reason} "
                    f"mode=0x{allocation.mode_id:08x} "
                    f"map=0x{allocation.map_id:04x} "
                    f"map_name={allocation.map_name!r} "
                    f"submode=0x{allocation.sub_mode_id:08x} "
                    f"flags=0x{allocation.room_flags:08x}",
                )
            except (KeyError, TypeError, ValueError, SpawnerError) as exc:
                log(
                    "DS-HANDOFF",
                    f"{reason} DS settings preparation failed "
                    f"mode=0x{mode_now:08x}: {type(exc).__name__}: {exc}; "
                    "no endpoint advertised",
                )
                return False
        elif room_id is None:
            # Covers allocator/quick-start paths that skipped A10A.
            try:
                allocation = V143B_DS_SPAWNER.reserve_lobby(
                    owner_id=int(role_state.get("uin") or 10001),
                    owner_nickname=_v150_role_nickname(role_state),
                    map_name=V143B_DS_CONFIG.default_map,
                    max_players=4,
                )
                role_state["v143b_ds_room_id"] = allocation.room_id
                room_id = allocation.room_id
            except SpawnerError as exc:
                log("DS-HANDOFF", f"stable-v143b lazy DS reservation failed: {exc}")
                # Do not send the stale fixed 65008 endpoint after allocation failure.
                return False

        try:
            # Track only this starter before arming. Other room members are
            # added when their own A11C SetInMatch confirms gameplay entry.
            V143B_DS_SPAWNER.begin_match(
                int(room_id), starter_uin=int(role_state.get("uin") or 10001)
            )
            # Start ONLY the bridge and wait for its UDP bind. AFDEV remains OFF.
            # The first valid DS packet sent by TGame to this bridge triggers v48.
            allocation = V143B_DS_SPAWNER.arm_lobby(int(room_id))
        except (SpawnerError, DSStartupError) as exc:
            log(
                "DS-HANDOFF",
                f"stable-v143b bridge arm failed room={room_id} "
                f"reason={reason}: {exc}",
            )
            return False

        handoff_host = allocation.public_host
        handoff_port = int(allocation.public_port)
        log(
            "DS-HANDOFF",
            f"stable-v143b bridge armed room={room_id} endpoint={handoff_host}:{handoff_port}; "
            f"AFDEV=OFF until first valid DS UDP packet",
        )

    try:
        ip_wire_value = _v143b_tdr_ipv4(handoff_host)
        domain = ""
        use_domain = 0
    except OSError:
        ip_wire_value = 0
        domain = handoff_host
        use_domain = 1

    ntf = _v87_build_ntf_start_match(
        port=handoff_port,
        ds_key=TGAME_DS_KEY,
        ip=ip_wire_value,
        domain=domain,
        is_use_domain=use_domain,
    )
    room_id_for_broadcast = None
    room_now = role_state.get("v79_created_match_room") or {}
    if room_now.get("room_id") is not None:
        room_id_for_broadcast = int(room_now["room_id"])
    elif role_state.get("v143b_ds_room_id") is not None:
        room_id_for_broadcast = int(role_state["v143b_ds_room_id"])

    desc = (
        "ZN2C_NTF_STARTMATCH r11 shared dynamic-DS "
        "cmd=0xA11A result=0x8100 "
        f"ds={handoff_host}:{handoff_port} "
        f"ip_value=0x{ip_wire_value:08x} "
        f"dskey_set={bool(TGAME_DS_KEY)} domain={domain!r} use_domain={use_domain}"
    )
    sent_uins = []
    room_snapshot_for_handoff = (
        V150_ROOM_REGISTRY.get_room(room_id_for_broadcast)
        if room_id_for_broadcast is not None
        else None
    )
    no_late_join_now = bool(
        isinstance(room_snapshot_for_handoff, dict)
        and room_snapshot_for_handoff.get("no_late_join")
    )

    if no_late_join_now:
        active_uins = sorted(
            int(x)
            for x in (
                getattr(allocation, "match_players", set())
                if allocation is not None
                else {_v150_role_uin(role_state)}
            )
        )
        for active_uin in active_uins:
            if _v150_send_online(
                active_uin,
                ntf,
                desc + " NoLateJoin-active-match-only",
            ):
                sent_uins.append(int(active_uin))
        log(
            "LATEJOIN",
            "v5.6 No Late Join active at StartMatch: "
            f"room={room_id_for_broadcast} A11A restricted to "
            f"match_players={active_uins} sent={sent_uins}",
        )
    else:
        sent_uins = (
            _v150_broadcast_room(room_id_for_broadcast, ntf, desc)
            if room_id_for_broadcast is not None
            else []
        )

    if not sent_uins:
        _v48_send_app(conn, active_tgame_key, ntf, label, desc + " fallback-direct")
        sent_uins = [_v150_role_uin(role_state)]

    now = time.time()
    with _V150_ZONE_LOCK:
        for sent_uin in sent_uins:
            session = _V150_ZONE_SESSIONS.get(int(sent_uin))
            rs = session.get("role_state") if session else None
            if isinstance(rs, dict):
                rs["v132_pve_afdev_handoff_sent"] = True
                rs["v132_pve_afdev_handoff_reason"] = str(reason)
                rs["v132_pve_afdev_handoff_at"] = now
                rs["v143b_ds_endpoint"] = f"{handoff_host}:{handoff_port}"

    role_state["v132_pve_afdev_handoff_sent"] = True
    role_state["v132_pve_afdev_handoff_reason"] = str(reason)
    role_state["v132_pve_afdev_handoff_at"] = now
    role_state["v143b_ds_endpoint"] = f"{handoff_host}:{handoff_port}"
    log(
        "DS-HANDOFF",
        f"stable-v143b PVE A11A -> allocated endpoint="
        f"{handoff_host}:{handoff_port} mode=0x{mode_now:08x} reason={reason} recipients={sent_uins}",
    )
    return True


def _latejoin_v2_send_running_match_a11a(
    conn,
    active_tgame_key,
    label,
    role_state,
    room_id,
    *,
    reason,
    commit_handoff=False,
):
    """Tell one late joiner about the already-running DS without rearming it.

    The recovered stock flow uses A11A as the notification that changes a
    non-owner room UI from Ready to Join game. A115 is then the explicit join
    action and the v26-recovered full A116 DSInfo completes that request.
    """
    requester_uin = _v150_role_uin(role_state)
    room_snapshot = V150_ROOM_REGISTRY.get_room(int(room_id))
    if (
        isinstance(room_snapshot, dict)
        and room_snapshot.get("started")
        and room_snapshot.get("no_late_join")
    ):
        log(
            "LATEJOIN",
            f"v5.6 No Late Join enforced uin={requester_uin} "
            f"room={int(room_id)} reason={reason}; requester-only A11A suppressed",
        )
        return False

    try:
        allocation = V143B_DS_SPAWNER.allocation_for_room(int(room_id))
    except Exception as exc:
        log(
            "LATEJOIN",
            f"v2 allocation lookup failed room={room_id}: {type(exc).__name__}: {exc}",
        )
        return False

    allocation_state = str(getattr(allocation, "state", "")) if allocation is not None else ""
    if allocation is None or allocation_state != "READY":
        log(
            "LATEJOIN",
            f"v5.4 room={room_id} DS not joinable state={allocation_state or '<missing>'} "
            f"reason={reason}; A11A suppressed",
        )
        return False

    handoff_host = str(allocation.public_host)
    handoff_port = int(allocation.public_port)
    try:
        ip_value = _v143b_tdr_ipv4(handoff_host)
        domain = ""
        use_domain = 0
    except OSError:
        ip_value = 0
        domain = handoff_host
        use_domain = 1

    ntf = _v87_build_ntf_start_match(
        port=handoff_port,
        ds_key=TGAME_DS_KEY,
        ip=ip_value,
        domain=domain,
        is_use_domain=use_domain,
    )
    _v48_send_app(
        conn,
        active_tgame_key,
        ntf,
        label,
        "ZN2C_NTF_STARTMATCH LATEJOIN-v2 requester-only "
        "cmd=0xA11A result=0x8100 "
        f"room={int(room_id)} ds={handoff_host}:{handoff_port} reason={reason}",
    )
    role_state["v143b_ds_endpoint"] = f"{handoff_host}:{handoff_port}"
    role_state["v150_latejoin_state_sync_sent"] = True
    if commit_handoff:
        role_state["v132_pve_afdev_handoff_sent"] = True
        role_state["v132_pve_afdev_handoff_reason"] = str(reason)
        role_state["v132_pve_afdev_handoff_at"] = time.time()

    log(
        "LATEJOIN",
        f"v2 requester-only A11A uin={_v150_role_uin(role_state)} "
        f"room={int(room_id)} endpoint={handoff_host}:{handoff_port} "
        f"commit_handoff={bool(commit_handoff)} reason={reason}",
    )
    return True


def _latejoin_v3_build_loading_state_ntf(seat_index):
    """Temporary v3 probe: publish EPlayerState_LoadingMatch(11) through A112.

    The stock PH enum recovered from UTGame is:
      8 Unready, 9 ReadyToMatch, 10 ReadyToObserve, 11 LoadingMatch, 12 InMatch.

    A112's verified wire layout is u16 SeatIndex + u32 PlayerState.  Normal
    ready currently uses state 9 on the same wire.  This v3 test checks whether
    a late joiner must first transition to LoadingMatch before A11A DSInfo can
    make it open the DS connection.
    """
    body = (
        _v48_u16(int(seat_index) & 0xFFFF)
        + _v48_u32(TGAME_PLAYERSTATE_LOADINGMATCH)
    )
    return _v62_build_server_app(
        TGAME_ZN_MAGIC,
        TGAME_ZN_NTF_SETMATCHROOMREADY,
        body,
    )


def _latejoin_v3_probe_ds_peer(room_id, uin):
    """Diagnostic only: verify whether late-join TGame ever reaches the bridge."""
    for delay in (0.50, 1.50, 3.00):
        time.sleep(delay)
        try:
            allocation = V143B_DS_SPAWNER.allocation_for_room(int(room_id))
            if allocation is None:
                log(
                    "LATEJOIN",
                    f"v3 DS probe +{delay:.2f}s uin={int(uin)} room={int(room_id)} "
                    "allocation=<missing>",
                )
                continue
            log(
                "LATEJOIN",
                f"v3 DS probe +{delay:.2f}s uin={int(uin)} room={int(room_id)} "
                f"state={getattr(allocation, 'state', None)} "
                f"peers={getattr(allocation, 'peer_count', None)} "
                f"live_peers={getattr(allocation, 'live_peer_count', None)} "
                f"room_players={sorted(int(x) for x in getattr(allocation, 'room_players', set()))} "
                f"match_players={sorted(int(x) for x in getattr(allocation, 'match_players', set()))} "
                f"trigger={getattr(allocation, 'trigger_client', None)}",
            )
        except Exception as exc:
            log(
                "LATEJOIN",
                f"v3 DS probe failed uin={int(uin)} room={int(room_id)}: "
                f"{type(exc).__name__}: {exc}",
            )


def _v72_parse_start_room_alloc(body):
    """Decode the fixed part of C2ZN_ReqStartRoomAlloc seen on the wire.

    Live body length is 46 bytes for one requested map:
      u64 PlayerUin
      32B MatchSettings
      u8  PlayerHardLevel
      u8  MapCount
      u32 MapIds[MapCount]

    The fixed MatchSettings layout used by the PH client captures includes
    ModeId, MapId, SubModeId, and room Flags at known offsets. Keep the full
    structure as well for diagnostics/future fields.
    """
    if len(body) < 42:
        raise ValueError(f"StartRoomAlloc body too short: {len(body)}B")
    uin = struct.unpack_from(">Q", body, 0)[0]
    match = body[8:40]
    hard_level = body[40]
    map_count = body[41]
    need = 42 + 4 * map_count
    if len(body) < need:
        raise ValueError(
            f"StartRoomAlloc truncated: map_count={map_count} "
            f"need={need} got={len(body)}"
        )
    maps = [struct.unpack_from(">I", body, 42 + 4*i)[0] for i in range(map_count)]
    mode_id = struct.unpack_from(">I", match, 0)[0] if len(match) >= 4 else None
    match_map_id = struct.unpack_from(">H", match, 4)[0] if len(match) >= 6 else None
    # Captured PH MatchSettings packs these fields at byte offsets 11 and 15.
    sub_mode_id = struct.unpack_from(">I", match, 11)[0] if len(match) >= 15 else None
    room_flags = struct.unpack_from(">I", match, 15)[0] if len(match) >= 19 else None
    return {
        "uin": uin,
        "match": match,
        "mode_id": mode_id,
        "match_map_id": match_map_id,
        "sub_mode_id": sub_mode_id,
        "room_flags": room_flags,
        "hard_level": hard_level,
        "map_count": map_count,
        "maps": maps,
        "consumed": need,
        "tail": body[need:],
    }


def _v72_build_enter_room_alloc_success():
    # ZN2C_NtfEnterRoomAlloc: diagnostic success Result only.
    return _v62_build_server_app(
        TGAME_ZN_MAGIC, TGAME_ZN_NTF_ENTERROOMALLOC,
        _v48_u16(ZONE_ERR_SUCC)
    )


def _v72_build_start_room_alloc_success():
    # ZN2C_ResStartRoomAlloc: diagnostic success Result only.
    return _v62_build_server_app(
        TGAME_ZN_MAGIC, TGAME_ZN_RES_STARTROOMALLOC,
        _v48_u16(ZONE_ERR_SUCC)
    )


def _v48_parse_createaccount(body):
    end = body.find(b"\x00")
    if end < 0:
        raise ValueError("CreateAccount nickname missing NUL")
    return body[:end].decode("latin1", "replace")


def _v57_next_server_seq(state):
    """Independent downstream frame sequence for one TGame connection."""
    seq = state.get("_v57_server_seq", 1)
    state["_v57_server_seq"] = (seq + 1) & 0xFFFFFFFF
    if state["_v57_server_seq"] == 0:
        state["_v57_server_seq"] = 1
    return seq


def _v48_send_app(conn, key, app_plain, label, desc, *, tpdu_cmd=0):
    # Downlink responses use TPDU cmd00; unsolicited server notifications use
    # cmd02, whose receive branch enters the normal client delivery path.
    # Both carry the same mode3-encrypted TDR package, starting at its magic
    # (0x8202 or 0x3243), without a client-style app sequence prefix.
    # r11: room notifications can originate from another ZONE thread, so every
    # write on a given TCP socket is serialized to prevent packet interleaving.
    tpdu_cmd = int(tpdu_cmd)
    if tpdu_cmd == 0:
        pkt, enc = tgame_build_cmd00_mode3(app_plain, key)
        tpdu_log_mode = "v57-cmd00-server-seq"
    elif tpdu_cmd == 2:
        pkt, enc = tgame_build_cmd02_mode3_body(app_plain, key)
        tpdu_log_mode = "v57-cmd02-notification"
    else:
        raise ValueError(f"unsupported downstream TPDU command 0x{tpdu_cmd:02x}")
    with _v150_conn_send_lock(conn):
        conn.sendall(pkt)
    log(
        label,
        f"TX {desc} {tpdu_log_mode} tpdu_cmd=0x{tpdu_cmd:02x} "
        f"plain_len={len(app_plain)} plain={app_plain.hex()} "
        f"enc_len={len(enc)} wire={_short_hex(pkt, 160)}"
    )
    return pkt


def tgame_build_cmd04_ident(key, mode, ident_plain):
    """Build TPDU_CMD_IDENT (cmd04) for a resumed TGame connection.

    TQQAPI v14 layout:
      TPDUBase(12) || u32 EncryptIdentLen || EncryptIdent

    EncryptIdent decrypts to TPDUIdentInfo:
      u32 Pos || char Ident[16]

    On reconnect we replay the exact validated 20-byte TPDUIdentInfo that the
    client presented inside cmd06, rather than inventing a new identity.
    """
    ident_plain = bytes(ident_plain or b"")
    if len(ident_plain) != 20:
        raise ValueError(
            f"TPDUIdentInfo must be exactly 20 bytes, got {len(ident_plain)}"
        )
    if mode == 3:
        enc = tgame_mode3_encrypt(ident_plain, key)
    elif mode == 4:
        enc = tgame_mode4_encrypt(ident_plain, key)
    else:
        raise ValueError(f"unsupported IDENT encryption mode {mode}")
    if len(enc) > 0xFFFFFFFF:
        raise ValueError("encrypted IDENT too large")
    total = 16 + len(enc)
    pkt = (
        b"\x55\x0e\x04\x00"
        + struct.pack(">I", total)
        + bytes(4)
        + struct.pack(">I", len(enc))
        + enc
    )
    if len(pkt) != total:
        raise AssertionError(
            f"cmd04 IDENT frame length mismatch: total={total} actual={len(pkt)}"
        )
    return pkt, enc


def tgame_build_cmd01_chgskey(old_key, mode, new_key=b"LOCAL_GAME_KEY01"):
    """Build the post-SYN key-change packet expected after cmd09.

    ProtocalHandler's cmd01 parser decrypts the encrypted body under the
    current mode and copies exactly 16 plaintext bytes into the new key.
    """
    if len(new_key) != 16:
        raise ValueError("new TGame key must be exactly 16 bytes")
    if mode == 3:
        enc = tgame_mode3_encrypt(new_key, old_key)
    elif mode == 4:
        enc = tgame_mode4_encrypt(new_key, old_key)
    else:
        raise ValueError(f"unsupported key-change mode {mode}")
    if len(enc) > 0xFFFF:
        raise ValueError("encrypted key-change body too large")

    # Compact wire layout: generic 12-byte header, then cmd-specific encrypted
    # length. cmd01 uses a 16-bit encrypted-length field internally.
    total = 16 + len(enc)
    pkt = (
        b"\x55\x0e\x01\x00"
        + struct.pack(">I", total)
        + bytes(4)
        + b"\x00\x00"
        + struct.pack(">H", len(enc))
        + enc
    )
    # For a 16-byte new key under mode 3, ciphertext is 32 bytes and the
    # compact cmd01 frame is exactly 48 bytes:
    #   12-byte TPDUBase + 2 reserved + 2-byte enc_len + ciphertext.
    if len(pkt) != total:
        raise AssertionError(
            f"cmd01 frame length mismatch: total={total} actual={len(pkt)}"
        )
    return pkt, enc, new_key


def tgame_build_cmd08_syn_auto(key, mode, randstr=TGAME_SYN_RAND):
    if len(randstr) != 16:
        raise ValueError("TPDUSynInfo.randstr must be exactly 16 bytes")
    if mode == 3:
        enc = tgame_mode3_encrypt(randstr, key)
    elif mode == 4:
        enc = tgame_mode4_encrypt(randstr, key)
    else:
        raise ValueError(f"TGame encryption mode {mode} is not implemented in v30")
    if len(enc) > 0xFF:
        raise ValueError("encrypted SYN too large")
    total = 13 + len(enc)
    pkt = (
        b"\x55\x0e\x08\x00" +
        struct.pack(">I", total) +
        b"\x00\x00\x00\x00" +
        bytes([len(enc)]) +
        enc
    )
    return pkt, enc


def tgame_read_loginkey_from_shared_memory(pid):
    """Read LoginKey from TCLS_SHAREDMEMEMORY<PID> without modifying it.

    Verified shared-memory layout:
      DWORD at +0x14 -> offset of the LoginKey byte-array field.
      At that field: little-endian DWORD length, followed by the bytes.
    The observed length is 16.
    """
    if os.name != "nt" or pid is None:
        return None, "not-windows/no-pid"

    import ctypes
    from ctypes import wintypes

    FILE_MAP_READ = 0x0004
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)

    k32.OpenFileMappingW.argtypes = [
        wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR
    ]
    k32.OpenFileMappingW.restype = wintypes.HANDLE
    k32.MapViewOfFile.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD,
        wintypes.DWORD, ctypes.c_size_t
    ]
    k32.MapViewOfFile.restype = ctypes.c_void_p
    k32.UnmapViewOfFile.argtypes = [ctypes.c_void_p]
    k32.UnmapViewOfFile.restype = wintypes.BOOL
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.CloseHandle.restype = wintypes.BOOL

    name = f"TCLS_SHAREDMEMEMORY{int(pid)}"
    h = k32.OpenFileMappingW(FILE_MAP_READ, False, name)
    if not h:
        return None, f"OpenFileMappingW({name}) failed err={ctypes.get_last_error()}"

    try:
        view = k32.MapViewOfFile(h, FILE_MAP_READ, 0, 0, 0)
        if not view:
            return None, f"MapViewOfFile failed err={ctypes.get_last_error()}"
        try:
            head = ctypes.string_at(view, 0x40)
            field_off = struct.unpack_from("<I", head, 0x14)[0]
            if field_off < 0x20 or field_off > 0x10000:
                return None, f"bad LoginKey field offset 0x{field_off:x}"

            field = ctypes.string_at(view + field_off, 4 + 64)
            n = struct.unpack_from("<I", field, 0)[0]
            if n != 16:
                return None, f"LoginKey length={n}, expected 16"

            key = bytes(field[4:20])
            return key, f"{name}+0x{field_off:x}"
        finally:
            k32.UnmapViewOfFile(view)
    finally:
        k32.CloseHandle(h)


def _aes_ecb_encrypt_block(block, key):
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(block) + enc.finalize()


def _aes_ecb_decrypt_block(block, key):
    dec = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    return dec.update(block) + dec.finalize()


def tgame_mode4_encrypt(plain, key):
    """Reimplementation of ProtocalHandler.dll mode-4 encrypt (0x1008BC40).

    Framing:
      random-high-nibble | padding-count
      padding-count random bytes
      2 random bytes
      payload
      7 zero trailer bytes

    Chaining:
      C[i] = AES(P[i] XOR C[i-1]) XOR P[i-1]
      C[-1] = P[-1] = 16 zero bytes
    """
    if len(key) != 16:
        raise ValueError("mode4 key must be 16 bytes")

    pad = (16 - ((len(plain) + 10) & 0x0F)) & 0x0F
    framed = bytearray()
    framed.append((os.urandom(1)[0] & 0xF0) | pad)
    if pad:
        framed += os.urandom(pad)
    framed += os.urandom(2)
    framed += plain
    framed += b"\x00" * 7

    if len(framed) & 0x0F:
        raise AssertionError("mode4 framed length is not block aligned")

    out = bytearray()
    prev_plain = bytes(16)
    prev_cipher = bytes(16)

    for off in range(0, len(framed), 16):
        p = bytes(framed[off:off + 16])
        x = bytes(a ^ b for a, b in zip(p, prev_cipher))
        y = _aes_ecb_encrypt_block(x, key)
        c = bytes(a ^ b for a, b in zip(y, prev_plain))
        out += c
        prev_plain = p
        prev_cipher = c

    return bytes(out)


def tgame_mode4_decrypt(ciphertext, key):
    """Inverse of ProtocalHandler.dll mode-4 framing; used to verify cmd09."""
    if len(key) != 16 or not ciphertext or (len(ciphertext) & 0x0F):
        return None, "bad mode4 input"

    framed = bytearray()
    prev_plain = bytes(16)
    prev_cipher = bytes(16)

    try:
        for off in range(0, len(ciphertext), 16):
            c = ciphertext[off:off + 16]
            y = bytes(a ^ b for a, b in zip(c, prev_plain))
            x = _aes_ecb_decrypt_block(y, key)
            p = bytes(a ^ b for a, b in zip(x, prev_cipher))
            framed += p
            prev_plain = p
            prev_cipher = c
    except Exception as e:
        return None, f"AES/dechain failed: {type(e).__name__}: {e}"

    pad = framed[0] & 0x0F
    start = 1 + pad + 2
    end = len(framed) - 7
    if start > end:
        return None, f"bad pad/start pad={pad} total={len(framed)}"
    if framed[end:] != b"\x00" * 7:
        return None, f"bad zero trailer framed={bytes(framed).hex()}"

    return bytes(framed[start:end]), "ok"



def _af_dword_to_le_bytes(hex_word):
    """x32dbg {x:[addr]} prints a DWORD value; convert to its 4 memory bytes."""
    value = int(hex_word, 16) & 0xFFFFFFFF
    return struct.pack("<I", value)


def _parse_af_crypto_records(raw):
    """Return [(position, key16, mode, description), ...] from AF11/AF8 logs."""
    out = []

    # AF11 records are preferred because they retain the connection handle and
    # print the key as four DWORDs. Reconstruct the original 16 memory bytes.
    af11_re = re.compile(
        r"\[AF11\]\s+SET\s+"
        r"caller=(?P<caller>[0-9A-Fa-f]+)\s+"
        r"conn=(?P<conn>[0-9A-Fa-f]+)\s+"
        r"keyptr=(?P<keyptr>[0-9A-Fa-f]+)\s+"
        r"k0=(?P<k0>[0-9A-Fa-f]+)\s+"
        r"k1=(?P<k1>[0-9A-Fa-f]+)\s+"
        r"k2=(?P<k2>[0-9A-Fa-f]+)\s+"
        r"k3=(?P<k3>[0-9A-Fa-f]+)\s+"
        r"mode=(?P<mode>\d+)"
    )
    for m in af11_re.finditer(raw):
        key = b"".join(
            _af_dword_to_le_bytes(m.group(name))
            for name in ("k0", "k1", "k2", "k3")
        )
        out.append((
            m.start(),
            key,
            int(m.group("mode")),
            f"AF11 conn={m.group('conn')} caller={m.group('caller')}",
        ))

    # Backward compatibility with the older AF8 logger.
    af8_re = re.compile(
        r"\[AF8\]\s+SetEncryptMethod\b.*?"
        r"conn=(?P<conn>[0-9A-Fa-f]+)\s+"
        r"keyptr=(?P<keyptr>[0-9A-Fa-f]+)\s+"
        r"key16=(?P<key>[0-9A-Fa-f]{32,})\s+"
        r"mode=(?P<mode>\d+)"
    )
    for m in af8_re.finditer(raw):
        out.append((
            m.start(),
            bytes.fromhex(m.group("key")[:32]),
            int(m.group("mode")),
            f"AF8 conn={m.group('conn')}",
        ))

    return out


def _candidate_x32dbg_logs(explicit=None):
    """Find likely x32dbg log files, newest first."""
    if explicit:
        return [Path(explicit)]

    env_path = os.environ.get("AF_X32DBG_LOG")
    if env_path:
        return [Path(env_path)]

    downloads = Path.home() / "Downloads"
    candidates = []
    if downloads.exists():
        seen = set()
        for pat in ("af*log*.txt", "*af*log*.txt"):
            for p in downloads.glob(pat):
                try:
                    rp = p.resolve()
                except Exception:
                    rp = p
                if rp in seen or not p.is_file():
                    continue
                seen.add(rp)
                candidates.append(p)

    # Preserve the old default as a final fallback.
    fallback = Path(os.environ.get("AF_FALLBACK_LOG_PATH", str(Path(__file__).resolve().parents[1] / "afafafafaflog.txt")))
    if fallback not in candidates:
        candidates.append(fallback)

    def _mtime(p):
        try:
            return p.stat().st_mtime
        except Exception:
            return -1.0

    candidates.sort(key=_mtime, reverse=True)
    return candidates


def tgame_read_x32dbg_live_crypto(log_path=None, expected_pid=None, wait_s=3.0, poll_s=0.05):
    """Read the freshest live AF11/AF8 SetEncryptMethod record.

    v40 intentionally does not hard-code one historical log filename. x32dbg
    log names can change between runs; using the old fixed path caused v39 to
    reuse a stale key from an earlier process.
    """
    deadline = time.time() + max(0.0, wait_s)
    last_err = "no AF11/AF8 crypto record found"

    while True:
        best = None  # (file_mtime, record_pos, key, mode, source)
        for p in _candidate_x32dbg_logs(log_path):
            try:
                raw = p.read_text(encoding="utf-8", errors="ignore")
                mtime = p.stat().st_mtime
            except Exception:
                continue

            # Bind a debugger log to the exact TGame process that owns this
            # ROLE socket. Reusing a fresh-looking log from another TGame PID
            # is still a wrong-key failure because the session key is per-process.
            log_pid = None
            m_pid = re.search(r"GetCurrentProcessId\s*=\s*(\d+)", raw)
            if m_pid:
                log_pid = int(m_pid.group(1))
            else:
                m_pid = re.search(r"\[P(\d+)\]", raw)
                if m_pid:
                    log_pid = int(m_pid.group(1))

            if expected_pid is not None and log_pid != int(expected_pid):
                continue

            records = _parse_af_crypto_records(raw)
            if not records:
                continue

            pos, key, mode, desc = records[-1]
            pid_desc = f" pid={log_pid}" if log_pid is not None else ""
            item = (mtime, pos, key, mode, f"{p}{pid_desc} {desc}")
            if best is None or item[:2] > best[:2]:
                best = item

        if best is not None:
            _, _, key, mode, source = best
            return key, mode, source

        if time.time() >= deadline:
            if expected_pid is not None:
                return None, None, (
                    f"no AF11/AF8 crypto record for current TGame PID={expected_pid}; "
                    "refusing to reuse another process's session key"
                )
            return None, None, last_err

        time.sleep(poll_s)

def tgame_parse_auth(data):
    """Parse the verified 0x55/0x0E TGame cmd03 AUTH wire shape."""
    if len(data) < 32 or data[0:3] != b"\x55\x0e\x03":
        return None

    total_len = struct.unpack(">I", data[4:8])[0]
    field0 = struct.unpack(">I", data[12:16])[0]
    field1 = struct.unpack(">I", data[16:20])[0]
    auth_type = struct.unpack(">I", data[20:24])[0]
    uin = struct.unpack(">I", data[24:28])[0]
    auth_len = struct.unpack(">I", data[28:32])[0]
    ticket = data[32:32 + auth_len]

    if (
        total_len < 32 + auth_len
        or total_len > len(data)
        or auth_type != 4
        or auth_len != 16
        or uin <= 0
        or len(ticket) != auth_len
        or any(character not in b"0123456789ABCDEF" for character in ticket)
    ):
        return None

    return {
        "total_len": total_len,
        "field0": field0,
        "field1": field1,
        "auth_type": auth_type,
        "uin": uin,
        "auth_len": auth_len,
        "ticket": ticket,
    }


def tgame_build_cmd08_syn(login_key, randstr=TGAME_SYN_RAND):
    """Build cmd08 exactly in the form consumed by ProtocalHandler+0x75C60."""
    if len(randstr) != 16:
        raise ValueError("TPDUSynInfo.randstr must be exactly 16 bytes")

    enc = tgame_mode4_encrypt(randstr, login_key)
    if len(enc) > 0xFF:
        raise ValueError("encrypted SYN too large")

    total = 13 + len(enc)
    pkt = bytearray()
    pkt += b"\x55\x0e\x08\x00"
    pkt += struct.pack(">I", total)
    pkt += b"\x00\x00\x00\x00"
    pkt += bytes([len(enc)])
    pkt += enc
    return bytes(pkt), enc


def tgame_decode_cmd09(data, login_key):
    lines = []
    if len(data) < 13:
        return [f"TGame follow-up too short: {len(data)}B"]

    total = struct.unpack(">I", data[4:8])[0]
    lines.append(
        f"TGame follow-up: magic={data[0]:02x} ver={data[1]:02x} "
        f"cmd={data[2]:02x} total={total} raw_len={len(data)}"
    )

    if data[0:2] != b"\x55\x0e" or data[2] != 0x09:
        return lines

    n = data[12]
    enc = data[13:13 + n]
    plain, status = tgame_mode4_decrypt(enc, login_key)
    lines.append(
        f"TGame SYNACK mode4={status} enc_len={n} "
        f"plain={plain.hex() if plain is not None else None} "
        f"matches={plain == TGAME_SYN_RAND if plain is not None else False}"
    )
    return lines

def handle_placeholder(conn, addr, label):
    """
    Temporary 65005 capture handler.

    It identifies the connecting process first, captures the first complete
    TCP burst, and keeps the socket alive long enough to observe follow-ups.
    """
    # Per-connection downstream sequence state. Reset for each accepted socket.
    state = {"_v57_server_seq": 1}
    try:
        server_port = conn.getsockname()[1]
        pid, process_name = identify_peer_process(addr, server_port)

        if pid is not None:
            log(
                label,
                f"Connected from {addr} OWNER="
                f"{process_name or '?'} PID={pid}"
            )
        else:
            log(
                label,
                f"Connected from {addr} OWNER=<unresolved>"
            )

        conn.settimeout(15.0)

        try:
            first = conn.recv(4096)
        except socket.timeout:
            first = b""

        if not first:
            log(label, "No data received")
            return

        packet = bytearray(first)

        # Collect fragments from the same initial burst.
        conn.settimeout(0.25)

        while len(packet) < 65536:
            try:
                chunk = conn.recv(4096)
            except socket.timeout:
                break

            if not chunk:
                break

            packet.extend(chunk)

        data = bytes(packet)

        owner = (
            f"{process_name or '?'} PID={pid}"
            if pid is not None
            else "unresolved"
        )

        is_tgame_service = label.upper() in ("ROLE", "ZONE", "DS-TCP")
        tgame_auth_wire = tgame_parse_auth(data) if is_tgame_service else None
        is_tgame_auth_packet = is_tgame_service and data[:3] == b"\x55\x0e\x03"
        is_tgame_resume_wire = is_tgame_service and data[:3] == b"\x55\x0e\x06"
        if tgame_auth_wire is not None:
            ticket_fingerprint = hashlib.sha256(
                tgame_auth_wire.get("ticket", b"")
            ).hexdigest()[:12]
            first_rx_summary = (
                f"{_short_hex(data[:32], 32)} "
                f"ticket_fp={ticket_fingerprint}"
            )
        elif is_tgame_auth_packet:
            first_rx_summary = (
                f"{_short_hex(data[:32], 32)} AUTH payload redacted"
            )
        elif is_tgame_resume_wire:
            first_rx_summary = (
                f"{_short_hex(data[:28], 28)} encrypted resume body redacted"
            )
        else:
            first_rx_summary = _short_hex(data, 96)

        log(
            label,
            f"FIRST RX COMPLETE ({len(data)}B) "
            f"OWNER={owner}: {first_rx_summary}",
            level="DEBUG",
        )

        if is_tgame_service and not is_tgame_resume_wire:
            for line in decode_role_packet_for_log(data):
                log(label, line)

        if not QUIET_ROLE_HEX and not is_tgame_auth_packet and not is_tgame_resume_wire:
            print(
                f"\n[{label}] OWNER: {owner}\n"
                f"[{label}] COPY THIS HEX:\n"
                f"{data.hex(' ')}\n",
                flush=True,
            )

        if len(data) >= 4:
            log(
                label,
                f"First bytes: {data[:16].hex(' ')}",
                level="DEBUG",
            )

            # ProtocalHandler's final send path forces byte[3] = 0x04.
            if data[2] == 0x03 and data[3] == 0x04:
                log(
                    label,
                    "SIGNATURE: compatible with ProtocalHandler AUTH "
                    "(cmd=03, wire byte[3]=04)"
                )

            elif data[2] == 0x03:
                log(
                    label,
                    f"NOTE: cmd-like byte is 03 but byte[3]={data[3]:02X}; "
                    "this does NOT match ProtocalHandler's final AUTH send buffer"
                )

        role_state = {}
        tgame_mode4_key = None
        tgame_crypto_mode = None
        tgame_session_ticket = None
        tgame_session_uin = None
        tgame_session_ip = addr[0]
        if label.upper() in ("ROLE", "ZONE", "DS-TCP"):
            # Remote TGame.exe cannot be identified by Windows PID from the VPS.
            # Recognize its ticket-bearing AUTH packet by the validated wire shape.
            tgame_auth = tgame_auth_wire

            if tgame_auth is not None:
                tgame_session_ticket = tgame_auth.get("ticket")
                tgame_session_uin = int(tgame_auth.get("uin") or 0)
                ticket_fingerprint = hashlib.sha256(
                    tgame_auth.get("ticket", b"")
                ).hexdigest()[:12]
                log(
                    label,
                    "TGame AUTH decoded: "
                    f"total={tgame_auth.get('total_len')} "
                    f"field0={tgame_auth.get('field0')} "
                    f"field1={tgame_auth.get('field1')} "
                    f"auth_type={tgame_auth.get('auth_type')} "
                    f"uin={tgame_auth.get('uin')} "
                    f"auth_len={tgame_auth.get('auth_len')} "
                    f"ticket_fp={ticket_fingerprint}"
                )

                # The AUTH DH exchange already established this AES key. The
                # successful AP result ties it to the opaque ticket that TGame
                # presents here, so the server can resume the handshake without a
                # client-side HTTPS helper or access to the remote process.
                tgame_mode4_key = None
                tgame_crypto_mode = None
                crypto_src = None
                _ticket_crypto = get_ticket_crypto(
                    tgame_auth.get("ticket", b""),
                    int(tgame_auth.get("uin") or 0),
                    addr[0],
                    db_path=PLAYER_DB.db_path,
                    private_key_path=PRIVATE_KEY_PATH,
                )
                if _ticket_crypto is not None:
                    tgame_mode4_key = _ticket_crypto["session_key"]
                    tgame_crypto_mode = int(_ticket_crypto["mode"])
                    crypto_src = "server AUTH ticket mapping"
                elif pid is not None and (process_name or "").lower() == "tgame.exe":
                    # Keep the exact local-process probe as a diagnostic
                    # fallback for a local test client. Remote players use the
                    # AUTH ticket mapping above; the server never reads their PC.
                    with _TGAME_USED_AUTH_ANCHORS_LOCK:
                        _used_auth_anchors = set(
                            _TGAME_USED_AUTH_ANCHORS.get(int(pid), set())
                        )

                    # The ZONE connection is a second live AuthAP object carrying
                    # the same ticket. Require a fresh anchor rather than reusing
                    # the GEO connection's key.
                    for _recover_try in range(10):
                        tgame_mode4_key, tgame_crypto_mode, crypto_src = (
                            tgame_recover_key_by_ticket(
                                pid=pid,
                                ticket=tgame_auth.get("ticket", b""),
                                exclude_anchors=_used_auth_anchors,
                            )
                        )
                        if tgame_mode4_key is not None:
                            break
                        time.sleep(0.05)

                    if (
                        tgame_mode4_key is not None
                        and isinstance(crypto_src, dict)
                        and crypto_src.get("anchor")
                    ):
                        try:
                            _chosen_anchor = int(str(crypto_src["anchor"]), 16)
                            with _TGAME_USED_AUTH_ANCHORS_LOCK:
                                _TGAME_USED_AUTH_ANCHORS.setdefault(
                                    int(pid), set()
                                ).add(_chosen_anchor)
                        except Exception:
                            pass
                else:
                    crypto_src = (
                        "no live AUTH key for this ticket, UIN, and client IP"
                    )
                if tgame_mode4_key is None and label.upper() == "DS-TCP":
                    # v95 controlled DS fallback:
                    # A11A handed this exact 16-byte value to TGame as
                    # GameServerInfo.DSKey.  Exact live-object recovery is
                    # still attempted first.  Only if that fails do we use
                    # the advertised DSKey as the mode-3 bootstrap key.
                    tgame_mode4_key = bytes(TGAME_DS_KEY)
                    tgame_crypto_mode = 3
                    crypto_src = {
                        "source": "A11A-DSKey-fallback",
                        "verified": False,
                    }
                    log(
                        label,
                        "v95 DS bootstrap fallback: "
                        "mode=3 source=A11A GameServerInfo.DSKey"
                    )

                if tgame_mode4_key is None:
                    log(label, f"TGame AUTH ticket key lookup FAILED: {crypto_src}")
                    log(label, "v95 sends no cmd08 because no TPDU bootstrap key is available.")
                elif tgame_crypto_mode not in (3, 4):
                    log(
                        label,
                        f"TGame ticket-anchor state mode={tgame_crypto_mode} "
                        f"source={crypto_src}; "
                        "unsupported for this SYN"
                    )
                else:
                    if isinstance(crypto_src, dict):
                        log(
                            label,
                            "TGame ticket-anchor crypto-state: "
                            f"mode={tgame_crypto_mode} "
                            f"verified={crypto_src.get('verified')} "
                            f"uin={crypto_src.get('uin')} "
                            f"service_id={crypto_src.get('service_id')} "
                            f"conn={crypto_src.get('conn')} "
                            f"anchor={crypto_src.get('anchor')} "
                            f"fresh={crypto_src.get('fresh_for_connection')} "
                            f"candidates={crypto_src.get('candidate_count')}"
                        )
                    else:
                        log(
                            label,
                            f"TGame ticket-anchor crypto-state: "
                            f"mode={tgame_crypto_mode} source={crypto_src}"
                        )

                    syn_t0 = time.perf_counter()
                    syn, syn_cipher = tgame_build_cmd08_syn_auto(
                        tgame_mode4_key, tgame_crypto_mode
                    )
                    syn_t1 = time.perf_counter()
                    conn.sendall(syn)
                    syn_t2 = time.perf_counter()
                    syn_build_ms = (syn_t1 - syn_t0) * 1000.0
                    syn_send_ms = (syn_t2 - syn_t1) * 1000.0
                    log(
                        label,
                        f"TX TGAME cmd08 SYN v42 ({len(syn)}B): {syn.hex()}",
                        level="DEBUG",
                    )
                    log(
                        label,
                        f"TGame SYN timing build_ms={syn_build_ms:.2f} "
                        f"send_ms={syn_send_ms:.2f}",
                        level=(
                            "WARNING"
                            if max(syn_build_ms, syn_send_ms) >= 1000.0
                            else "DEBUG"
                        ),
                    )
                    log(
                        label,
                        f"TX TGAME SYN challenge={TGAME_SYN_RAND!r} "
                        f"mode={tgame_crypto_mode} cipher_len={len(syn_cipher)}; "
                        "waiting for cmd09 SYNACK"
                    )

                role_state = {
                    "tgame": True,
                    "uin": int(tgame_auth.get("uin") or 10001),
                }
                _v140_select_player(role_state["uin"])

                # v159: stock PH visually initializes a fresh lobby on Bag 1.
                # Align a genuinely fresh TGame auth with that client state.
                # The separate persistent-resume path remains unchanged.
                _v159_before_bag = _v141_current_bag_gid()
                _v159_startup_bag, _v159_startup_changes = (
                    _v141_set_current_bag(
                        V109_BAG1_GID,
                        reason="v159-fresh-session-default",
                    )
                )
                if (
                    int(_v159_startup_bag) != int(_v159_before_bag)
                    or _v159_startup_changes
                ):
                    _v140_save_state("v159-fresh-session-default")
                role_state["v159_startup_bag_gid"] = int(_v159_startup_bag)
                log(
                    "MALL-BAG",
                    "v159 fresh-session bag aligned with stock lobby "
                    f"before=0x{int(_v159_before_bag):016x} "
                    f"selected=0x{int(_v159_startup_bag):016x} "
                    f"changes={len(_v159_startup_changes)}; "
                    "persistent-resume path intentionally unchanged",
                )

                _persist_login, _persist_nick = _r12_load_persisted_nickname(
                    role_state["uin"]
                )
                if _persist_login:
                    role_state["login_name"] = _persist_login
                if _persist_nick:
                    role_state["nickname"] = _persist_nick
                    log(
                        "NICKNAME",
                        "SQLite nickname restored on TGame auth: "
                        f"uin={role_state['uin']} login={_persist_login!r} "
                        f"nickname={_persist_nick!r}",
                    )
            else:
                role_state = role_extract_auth_state(data)
                if (
                    label.upper() in ("ROLE", "ZONE")
                    and len(data) >= 3
                    and data[:3] == b"\x55\x0e\x06"
                ):
                    # cmd06 resumes an established transport session. Decrypt
                    # the UIN and sequence with each candidate key, then match
                    # the UIN before accepting the reconnect.
                    try:
                        _resume_candidates = get_sessions_for_ip(
                            addr[0],
                            db_path=PLAYER_DB.db_path,
                            private_key_path=PRIVATE_KEY_PATH,
                        )
                    except Exception as _resume_error:
                        _resume_candidates = []
                        log(
                            label,
                            "Persistent TGame session lookup failed: "
                            f"{type(_resume_error).__name__}",
                        )
                    _resume_matches = []
                    if len(_resume_candidates) > 1:
                        log(
                            label,
                            "Persistent TGame multi-session lookup "
                            f"ip={addr[0]} candidates={len(_resume_candidates)}; "
                            "authenticating cmd06 against every candidate key/UIN",
                        )
                    for _candidate in _resume_candidates:
                        _candidate_key = _candidate.get("transport_key")
                        if _candidate_key is None:
                            continue
                        try:
                            _cmd06 = parse_cmd06_resume(
                                data,
                                bytes(_candidate_key),
                                tgame_mode3_decrypt,
                            )
                            # PH v14 cmd06 is NOT laid out like the older
                            # TPDUExtRelay XML at wire offsets 12..28. The
                            # verified parser proves those fields are:
                            #   EncMethod, ServiceID, reserved, EncHeadLen
                            # and the encrypted header plaintext starts with
                            # UIN. Live-compatible framing is:
                            #   UIN(u32) || TPDUIdentInfo(20 bytes)
                            # where TPDUIdentInfo = Pos(u32) || Ident[16].
                            # Reuse that exact decrypted identity for cmd04.
                            _relay_head_len = struct.unpack(">I", data[4:8])[0]
                            _relay_header_plain = tgame_mode3_decrypt(
                                data[28:_relay_head_len], bytes(_candidate_key)
                            )
                            if len(_relay_header_plain) < 24:
                                raise ValueError(
                                    "cmd06 decrypted header too short for UIN+TPDUIdentInfo"
                                )
                            _relay_ident_plain = bytes(_relay_header_plain[4:24])
                            _cmd06["ident_plain"] = _relay_ident_plain
                            _cmd06["ident_pos"] = struct.unpack(
                                ">I", _relay_ident_plain[:4]
                            )[0]
                            _cmd06["header_plain_len"] = len(_relay_header_plain)
                        except Exception:
                            continue
                        if _cmd06["uin"] == int(_candidate["uin"]):
                            _resume_matches.append((_candidate, _cmd06))

                    _resume_uins = {
                        int(candidate["uin"])
                        for candidate, _request in _resume_matches
                    }
                    if len(_resume_uins) == 1:
                        # Multi-user hosted mode: many UINs may coexist. Repeated logins
                        # for the SAME account may leave several durable tickets;
                        # use that account's most recently active matching ticket.
                        _resume, _cmd06 = max(
                            _resume_matches,
                            key=lambda match: float(match[0]["last_seen_at"]),
                        )
                        tgame_mode4_key = bytes(_resume["transport_key"])
                        tgame_crypto_mode = int(_resume["mode"])
                        tgame_session_ticket = str(
                            _resume["ticket"]
                        ).encode("ascii")
                        tgame_session_uin = int(_resume["uin"])
                        try:
                            touch_session(
                                tgame_session_ticket,
                                tgame_session_uin,
                                tgame_session_ip,
                                db_path=PLAYER_DB.db_path,
                            )
                        except Exception as _resume_touch_error:
                            log(
                                label,
                                "Persistent TGame session expiry refresh failed "
                                f"during resume: {type(_resume_touch_error).__name__}",
                            )
                        role_state = {
                            "tgame": True,
                            "uin": tgame_session_uin,
                            "persistent_resume": True,
                            # cmd06 is the client's transport continuity marker.
                            # Keep it so the post-SYNACK resume path can derive
                            # the same diagnostic sequence window as normal A000.
                            "persistent_resume_client_seq": int(_cmd06["sequence"]),
                            "persistent_resume_service_id": int(_cmd06.get("service_id", 0)),
                            "persistent_resume_header_plain_len": int(_cmd06.get("header_plain_len", 0)),
                            "persistent_resume_ident_pos": int(_cmd06.get("ident_pos", 0)),
                            "persistent_resume_ident_plain": bytes(
                                _cmd06.get("ident_plain") or b""
                            ),
                        }
                        _v140_select_player(tgame_session_uin)
                        _persist_login, _persist_nick = (
                            _r12_load_persisted_nickname(tgame_session_uin)
                        )
                        if _persist_login:
                            role_state["login_name"] = _persist_login
                        if _persist_nick:
                            role_state["nickname"] = _persist_nick
                        _resume_room = V150_ROOM_REGISTRY.room_for_player(
                            tgame_session_uin
                        )
                        if _resume_room is not None:
                            _resume_member = next(
                                (
                                    member
                                    for member in _resume_room.get("members", [])
                                    if int(member.get("uin", 0))
                                    == tgame_session_uin
                                ),
                                None,
                            )
                            if _resume_member is not None:
                                role_state["persistent_resume_room"] = _resume_room
                                role_state["v79_created_match_room"] = _resume_room
                                role_state["v143b_ds_room_id"] = int(
                                    _resume_room["room_id"]
                                )
                                role_state["v83_in_match_room"] = True
                                role_state["v88_match_seat"] = int(
                                    _resume_member.get("seat_index", 0)
                                )
                                role_state["v88_match_camp"] = int(
                                    _resume_member.get("camp", 1)
                                )
                                log(
                                    label,
                                    "Persistent TGame room state restored "
                                    f"uin={tgame_session_uin} "
                                    f"room={int(_resume_room['room_id'])} "
                                    f"members={len(_resume_room.get('members', []))}",
                                )
                        _resume_remaining = max(
                            0,
                            int(float(_resume["expires_at"]) - time.time()),
                        )
                        log(
                            label,
                            "Persistent TGame cmd06 authenticated "
                            f"uin={tgame_session_uin} "
                            f"client_seq=0x{_cmd06['sequence']:08x} "
                            f"service_id={int(_cmd06.get('service_id', 0))} "
                            f"header_plain_len={int(_cmd06.get('header_plain_len', 0))} "
                            f"ident_pos=0x{int(_cmd06.get('ident_pos', 0)):08x} "
                            f"expires_in={_resume_remaining}s",
                        )
                        syn, syn_cipher = tgame_build_cmd08_syn_auto(
                            tgame_mode4_key, tgame_crypto_mode
                        )
                        conn.sendall(syn)
                        log(
                            label,
                            f"TX TGAME cmd08 SYN for persistent resume "
                            f"({len(syn)}B) mode={tgame_crypto_mode} "
                            f"cipher_len={len(syn_cipher)}; waiting for cmd09 SYNACK",
                        )
                    elif len(_resume_uins) > 1:
                        log(
                            label,
                            "Persistent TGame cmd06 matches multiple accounts "
                            f"for this client IP: candidates={len(_resume_uins)}; "
                            "not resuming",
                        )
                    else:
                        log(
                            label,
                            "No unexpired persistent TGame session "
                            "authenticated this cmd06 packet",
                        )
            if not role_state.get("tgame"):
                log(
                    label,
                    f"live auth state: mode={role_state.get('mode')} "
                    f"uin={role_state.get('uin')} seq={role_state.get('seq')} "
                    f"session_key_present={bool(role_state.get('session_key'))} "
                    f"body_status={role_state.get('body_status')}",
                )
            app_plain = role_state.get("app_plain") or b""
            if len(app_plain) >= 14:
                try:
                    app_len = int.from_bytes(app_plain[0:4], "big")
                    magic = int.from_bytes(app_plain[4:6], "big")
                    ver = int.from_bytes(app_plain[6:8], "big")
                    cmdid = int.from_bytes(app_plain[8:10], "big")
                    app_seq = int.from_bytes(app_plain[10:14], "big")
                    app_uin = int.from_bytes(app_plain[14:18], "big") if len(app_plain) >= 18 else None
                    log(
                        label,
                        f"TACC request decoded: len={app_len} magic=0x{magic:04x} "
                        f"ver={ver} cmdid={cmdid} app_seq={app_seq} "
                        f"app_uin={app_uin} raw={app_plain.hex()}",
                        level="DEBUG",
                    )
                except Exception as e:
                    log(label, f"TACC request parse error: {e}")
            if label.upper() == "ROLE" and (not role_state.get("tgame")) and role_state.get("mode") == 3 and role_state.get("session_key") and role_state.get("seq") is not None:
                # v5: this ROLE connection is client.exe / CPlayerInfoQuerier.
                # It already sent an authenticated TPDU cmd03 with a TACC request body.
                # The correct next server message is a TPDU cmd05 carrying TACC_CMD_RSP,
                # not a cmd08 SYN challenge.
                app, priv_payload = role_build_tacc_one_private_entry_app(
                    uin=role_state.get("uin") or 10001,
                    server_id=0x01010101,
                    host="127.0.0.1",
                    port=65005,
                    cmdid=2,
                    update_time=int(time.time()),
                )
                # Echo the client's TPDU sequence. v6 used echo; v7 used +1.
                # The payload content, not the TPDU seq, is the new variable here.
                rsp, body_plain, body_cipher = role_build_plain_tpdu_body_response(
                    role_state["session_key"],
                    role_state["seq"] & 0xffffffff,
                    app,
                )
                conn.sendall(rsp)
                log(label, f"TX TACC-RSP v26 tgame-mode4-syn-probe ({len(rsp)}B) app_len={len(app)} body_cipher_len={len(body_cipher)} client_seq={role_state['seq']} uin={role_state.get('uin')}")
                log(label, f"TX TACC-RSP v26 server_id=0x01010101 private_data={priv_payload.hex()} ; waiting for TGame/next connection")
            elif not role_state.get("tgame"):
                log(label, "Not sending TACC-RSP: live mode3/session key/sequence was not recovered")

        log(
            label,
            "Keeping connection open for follow-up handshake traffic"
        )

        followup_seconds = 3600.0 if label.upper() in ("ZONE", "DS-TCP") else 120.0
        deadline = time.time() + followup_seconds
        log(label, f"Follow-up receive lifetime={followup_seconds:.0f}s")
        conn.settimeout(1.0)

        # Transport crypto state changes immediately after a successful cmd01.
        active_tgame_key = tgame_mode4_key
        active_tgame_mode = locals().get("tgame_crypto_mode")
        tgame_chgskey_complete = False

        # TCP is a byte stream, not a packet API.  Stream framing must be
        # active from the FIRST live TGame follow-up, not only after CHGSKEY.
        #
        # The PH client can coalesce a normal cmd00 packet and the cmd09
        # SYNACK into one recv().  Waiting until CHGSKEY to enable splitting
        # loses the queued SYNACK and the client eventually reports
        # "Connect time out".
        tgame_stream_mode = bool(
            role_state.get("tgame") and tgame_mode4_key is not None
        )
        tgame_stream_tail = b""
        tgame_stream_frame_queue = []
        tgame_last_persist_touch = 0.0

        # v69 diagnostic:
        # The client consistently sends FF05 only *after* accepting A001.
        # Do not push A005/A006/FF13 before that client-side milestone.
        pending_zone_profile = None

        while time.time() < deadline:
            # Consume exactly one complete TGame TPDU at a time. Extra frames
            # from the same recv() stay queued, including a cmd09 SYNACK that
            # arrives behind a pre-CHGSKEY cmd00 packet.
            if tgame_stream_mode and tgame_stream_frame_queue:
                extra = tgame_stream_frame_queue.pop(0)
                log(
                    label,
                    f"FOLLOW-UP FRAME ({len(extra)}B) from queued TCP data "
                    f"OWNER={owner}: {_short_hex(extra, 96)}"
                )
            else:
                try:
                    rx_chunk = conn.recv(4096)
                except socket.timeout:
                    continue

                if not rx_chunk:
                    log(label, "Client closed connection; if this was client.exe after TACC-RSP, that can be normal. Watch for next VERSION/ROLE owner=TGame.exe.")
                    break

                if tgame_stream_mode:
                    combined = tgame_stream_tail + rx_chunk
                    try:
                        frames, tgame_stream_tail = tgame_split_generic_stream(
                            combined
                        )
                    except Exception as e:
                        log(
                            label,
                            f"TGame TCP stream split ERROR: {type(e).__name__}: {e}; "
                            f"combined={_short_hex(combined, 160)}"
                        )
                        # Diagnostic fallback for a malformed/unknown frame.
                        extra = combined
                        tgame_stream_tail = b""
                    else:
                        log(
                            label,
                            f"FOLLOW-UP RX CHUNK ({len(rx_chunk)}B) "
                            f"OWNER={owner}: complete_frames={len(frames)} "
                            f"tail={len(tgame_stream_tail)}B "
                            f"{_short_hex(rx_chunk, 96)}"
                        )
                        if not frames:
                            continue
                        extra = frames.pop(0)
                        tgame_stream_frame_queue.extend(frames)
                        log(
                            label,
                            f"FOLLOW-UP FRAME ({len(extra)}B) "
                            f"OWNER={owner}: {_short_hex(extra, 96)}"
                        )
                else:
                    extra = rx_chunk
                    log(
                        label,
                        f"FOLLOW-UP RX ({len(extra)}B) "
                        f"OWNER={owner}: {_short_hex(extra, 96)}"
                    )
            if label.upper() in ("ROLE", "ZONE", "DS-TCP"):
                if tgame_mode4_key is not None:
                    mode_now = locals().get("tgame_crypto_mode")
                    if mode_now == 3:
                        try:
                            if len(extra) >= 3 and extra[2] == 0x09:
                                # SYNACK uses the cmd-specific head extension.
                                cmd_now, total_now, enc_now = tgame_parse_wire_encrypted_body(extra)
                                plain_now = tgame_mode3_decrypt(enc_now, active_tgame_key)
                                log(
                                    label,
                                    f"TGame mode3 follow-up cmd=0x{cmd_now:02x} "
                                    f"total={total_now} plain={_clan_debug_hex(plain_now)}"
                                )
                                if plain_now == TGAME_SYN_RAND:
                                    log(label, "TGame SYNACK verified: challenge echo matches")

                                    # TPDU relay/reconnect completion: the stock
                                    # TQQAPI state machine sends IDENT (cmd04)
                                    # before CHGSKEY after SYNACK. Fresh AF login
                                    # happens to tolerate our old CHGSKEY-only path,
                                    # but a cmd06 RELAY remains in reconnect state
                                    # without the connection-established IDENT.
                                    if (
                                        role_state.get("persistent_resume")
                                        and label.upper() == "ZONE"
                                    ):
                                        _resume_ident_plain = bytes(
                                            role_state.get(
                                                "persistent_resume_ident_plain"
                                            ) or b""
                                        )
                                        ident_pkt, ident_enc = tgame_build_cmd04_ident(
                                            active_tgame_key,
                                            mode_now,
                                            _resume_ident_plain,
                                        )
                                        conn.sendall(ident_pkt)
                                        log(
                                            label,
                                            "TX TGAME cmd04 IDENT for persistent resume "
                                            f"({len(ident_pkt)}B) "
                                            f"service_id={int(role_state.get('persistent_resume_service_id', 0))} "
                                            f"header_plain_len={int(role_state.get('persistent_resume_header_plain_len', 0))} "
                                            f"ident_pos=0x{int(role_state.get('persistent_resume_ident_pos', 0)):08x} "
                                            f"enc_len={len(ident_enc)}; "
                                            "replayed cmd06 decrypted-header TPDUIdentInfo",
                                        )

                                    chg, chg_enc, new_key = tgame_build_cmd01_chgskey(
                                        active_tgame_key, mode_now
                                    )
                                    conn.sendall(chg)
                                    active_tgame_key = new_key
                                    active_tgame_mode = mode_now
                                    tgame_chgskey_complete = True
                                    tgame_stream_mode = True
                                    if (
                                        tgame_session_ticket is not None
                                        and tgame_session_uin is not None
                                    ):
                                        try:
                                            _persisted = save_transport_key(
                                                tgame_session_ticket,
                                                tgame_session_uin,
                                                tgame_session_ip,
                                                new_key,
                                                mode=mode_now,
                                                db_path=PLAYER_DB.db_path,
                                                private_key_path=PRIVATE_KEY_PATH,
                                            )
                                            if _persisted:
                                                tgame_last_persist_touch = time.monotonic()
                                                log(
                                                    label,
                                                    "Persistent TGame transport session saved "
                                                    f"for uin={tgame_session_uin}",
                                                )
                                            else:
                                                log(
                                                    label,
                                                    "Persistent TGame transport session was not "
                                                    "updated (ticket missing, expired, or IP mismatch)",
                                                )
                                        except Exception as _persist_error:
                                            log(
                                                label,
                                                "Persistent TGame transport session save failed: "
                                                f"{type(_persist_error).__name__}",
                                            )
                                    # Do NOT clear tgame_stream_frame_queue or
                                    # tgame_stream_tail here.  TCP may already
                                    # have delivered another complete/partial
                                    # frame next to the SYNACK.
                                    log(
                                        label,
                                        f"TX TGAME cmd01 CHGSKEY v44 ({len(chg)}B) "
                                        f"new_key=<redacted> enc_len={len(chg_enc)}: "
                                        f"{_short_hex(chg, 96)}"
                                    )
                                    log(
                                        label,
                                        "TGame transport key switched locally; subsequent "
                                        "cmd00 body traffic will be decrypted with the new key"
                                    )
                                    if (
                                        role_state.get("persistent_resume")
                                        and label.upper() == "ZONE"
                                    ):
                                        # Verified restart-resume path: after
                                        # cmd06 -> cmd08 -> cmd09 -> cmd04 -> cmd01,
                                        # stock PH does not send a fresh A000. Replay
                                        # the already-proven A001 login response, then
                                        # let the normal FF05 deferred-profile path run.
                                        uin_now = _v150_role_uin(role_state)
                                        _V140_PLAYER_STATE.reload(uin_now)
                                        persisted_nickname = PLAYER_DB.load_nickname(uin_now)
                                        awaiting_first_nickname = persisted_nickname is None
                                        role_state[
                                            "v5_awaiting_first_nickname"
                                        ] = awaiting_first_nickname

                                        resume_base_seq = int(
                                            role_state.get(
                                                "persistent_resume_client_seq", 0
                                            )
                                        ) & 0xFFFFFFFF
                                        seq_login = (resume_base_seq + 1) & 0xFFFFFFFF
                                        seq_pinfo = (resume_base_seq + 2) & 0xFFFFFFFF
                                        seq_props = (resume_base_seq + 3) & 0xFFFFFFFF
                                        seq_hints = (resume_base_seq + 4) & 0xFFFFFFFF
                                        login_result = (
                                            0x0401
                                            if awaiting_first_nickname
                                            else ZONE_ERR_SUCC
                                        )
                                        login_rsp = _v48_build_zn_login_response(
                                            seq_login,
                                            result=login_result,
                                            expose_wallet=not awaiting_first_nickname,
                                        )
                                        _v48_send_app(
                                            conn,
                                            active_tgame_key,
                                            login_rsp,
                                            label,
                                            "ZN2C_RES_LOGIN RESTART-RESUME-IDENT-A001 "
                                            f"result=0x{login_result:04x} "
                                            f"uin={uin_now} "
                                            f"resume_client_seq=0x{resume_base_seq:08x} "
                                            f"nickname={persisted_nickname!r}",
                                        )

                                        if awaiting_first_nickname:
                                            # Mirror the normal A000 first-account gate.
                                            role_state["v12_force_blank_nickname"] = True
                                            role_state["v13_no_role_login"] = True
                                            role_state["v20_force_a001_0401"] = True
                                            pending_zone_profile = None
                                            log(
                                                label,
                                                "Persistent resume A001 sent with result=0x0401; "
                                                "first-nickname profile remains withheld",
                                            )
                                        else:
                                            role_state.pop(
                                                "v12_force_blank_nickname", None
                                            )
                                            role_state.pop(
                                                "v13_no_role_login", None
                                            )
                                            pending_zone_profile = {
                                                "seq_pinfo": seq_pinfo,
                                                "seq_props": seq_props,
                                                "seq_hints": seq_hints,
                                                "first_nickname_probe": False,
                                            }
                                            log(
                                                label,
                                                "Persistent TGame transport resumed; "
                                                "proactive A001 replay sent; waiting for FF05 "
                                                "instead of waiting for a fresh A000",
                                            )
                                else:
                                    log(
                                        label,
                                        f"TGame SYNACK plaintext mismatch expected={TGAME_SYN_RAND.hex()}"
                                    )
                            else:
                                # Normal post-handshake traffic uses the generic
                                # 12-byte TPDUBase and encrypted BodyLen bytes.
                                cmd_now, head_now, body_len_now, enc_now = (
                                    tgame_parse_generic_body(extra)
                                )
                                plain_now = tgame_mode3_decrypt(
                                    enc_now, active_tgame_key
                                )
                                phase = (
                                    "post-CHGSKEY"
                                    if tgame_chgskey_complete
                                    else "pre-CHGSKEY"
                                )
                                log(
                                    label,
                                    f"TGame {phase} cmd=0x{cmd_now:02x} "
                                    f"head_len={head_now} body_len={body_len_now} "
                                    f"plain_len={len(plain_now)} plain={_clan_debug_hex(plain_now)}"
                                )

                                if cmd_now == 0x0D:
                                    close_seq = (
                                        struct.unpack(">I", plain_now[:4])[0]
                                        if len(plain_now) >= 4 else None
                                    )
                                    log(
                                        label,
                                        "TGame TPDU CLOSE "
                                        + (
                                            f"seq=0x{close_seq:08x}"
                                            if close_seq is not None
                                            else f"plain={_clan_debug_hex(plain_now)}"
                                        )
                                    )
                                    continue

                                # v48 application dispatcher.  The ROLE socket
                                # carries C2GEO (0x8202).  After ZoneList the
                                # client opens a NEW connection to port 65006,
                                # repeats the same TPDU handshake, then carries
                                # C2ZN (0x3243) inside cmd00.
                                try:
                                    app = _v48_parse_app(plain_now)
                                    if (
                                        tgame_session_ticket is not None
                                        and tgame_session_uin is not None
                                        and time.monotonic() - tgame_last_persist_touch >= TGAME_SESSION_TOUCH_INTERVAL_SECONDS
                                    ):
                                        try:
                                            if touch_session(
                                                tgame_session_ticket,
                                                tgame_session_uin,
                                                tgame_session_ip,
                                                db_path=PLAYER_DB.db_path,
                                            ):
                                                tgame_last_persist_touch = time.monotonic()
                                        except Exception as _touch_error:
                                            log(
                                                label,
                                                "Persistent TGame session expiry refresh failed: "
                                                f"{type(_touch_error).__name__}",
                                            )
                                    log(
                                        label,
                                        "TGame APP: "
                                        f"seq=0x{app['seq']:08x} "
                                        f"magic=0x{app['magic']:04x} "
                                        f"cmd=0x{app['cmd']:04x} "
                                        f"head_len={app['head_len']} "
                                        f"body_len={app['body_len']} "
                                        f"body={'<clan credentials redacted>' if app['cmd'] in CLAN_SENSITIVE_COMMANDS else _short_hex(app['body'], 128)}"
                                    )

                                    if label.upper() == "DS-TCP":
                                        log(
                                            label,
                                            "v95 DS APPLICATION CAPTURE: "
                                            f"seq=0x{app['seq']:08x} "
                                            f"magic=0x{app['magic']:04x} "
                                            f"cmd=0x{app['cmd']:04x} "
                                            f"head_len={app['head_len']} "
                                            f"body_len={app['body_len']} "
                                            f"full_plain={_clan_debug_hex(plain_now)}"
                                        )
                                        # Do not accidentally feed DS traffic
                                        # to GEO/ZONE handlers.  The next
                                        # server reply will be built only after
                                        # this exact request is known.
                                        continue

                                    if app["magic"] == TGAME_ZN_MAGIC:
                                        _v139_trace_c2zn_request(
                                            app["cmd"],
                                            app["body"],
                                            label,
                                        )

                                    if app["magic"] == TGAME_GEO_MAGIC:
                                        if app["cmd"] == TGAME_GEO_REQ_PINGLIST:
                                            # Runtime v60: x32dbg proved two wire-format fixes.
                                            # 1) Response cmd00 plaintext begins at GEO magic 0x8202;
                                            #    do NOT prepend/echo the client's 4-byte app sequence.
                                            # 2) PingInfo.Domain is u32_be(strlen+1) + NUL string,
                                            #    making BodyLen=0x22 and app plaintext length 0x2A.
                                            client_seq = app["seq"] & 0xffffffff
                                            log(
                                                label,
                                                f"GEO PingList runtime-verified response: "
                                                f"client_rx_seq=0x{client_seq:08x} "
                                                "response_seq_prefix=NONE "
                                                "domain_len_prefix=u32be"
                                            )
                                            rsp_plain = tgame_build_geo_pinglist_response(
                                                client_seq, max_delay_ms=1000
                                            )
                                            _v48_send_app(
                                                conn, active_tgame_key, rsp_plain,
                                                label,
                                                "TGAME GEO2C_RES_PINGLIST v61-ping-verified "
                                                "seq_prefix=NONE body_len=0x22 "
                                                "result=0x8B00 servers=1 "
                                                "target=127.0.0.1 max_delay_ms=1000"
                                            )

                                        elif app["cmd"] == TGAME_GEO_REQ_ZONELIST:
                                            zreq = _v48_parse_geo_req_zonelist(
                                                app["body"]
                                            )
                                            log(
                                                label,
                                                "C2GEO_REQ_ZONELIST ACCEPTANCE SIGNAL: "
                                                f"count={zreq['count']} "
                                                f"servers={zreq['servers']} "
                                                f"max_delay_ms={zreq['max_delay_ms']} "
                                                f"consumed={zreq['consumed']}/{zreq['body_len']}"
                                            )
                                            client_seq = app["seq"] & 0xffffffff
                                            client_ping_ms = (
                                                int(zreq["servers"][0]["ping_ms"]) & 0xffffffff
                                                if zreq["servers"]
                                                else 0xfffffffe
                                            )
                                            client_ping_signed = (
                                                client_ping_ms
                                                if client_ping_ms < 0x80000000
                                                else client_ping_ms - 0x100000000
                                            )
                                            log(
                                                label,
                                                "GEO ZoneList response derived from accepted PingList framing: "
                                                f"client_rx_seq=0x{client_seq:08x} "
                                                f"client_ping_ms_u32={client_ping_ms} "
                                                f"client_ping_ms_signed={client_ping_signed} "
                                                "response_seq_prefix=NONE "
                                                "domain_len_prefix=u32be"
                                            )
                                            zrsp = _v48_build_geo_zonelist(
                                                client_seq,
                                                port=TGAME_ZONE_PORT,
                                                ping_ms=client_ping_ms,
                                            )
                                            _v48_send_app(
                                                conn, active_tgame_key, zrsp,
                                                label,
                                                "TGAME GEO2C_RES_ZONELIST v61-no-seq-u32-domain "
                                                "seq_prefix=NONE body_len=0x3E "
                                                "result=0x8B00 zones=1 "
                                                f"target=127.0.0.1:{TGAME_ZONE_PORT} "
                                                f"ping_ms_u32={client_ping_ms} "
                                                f"ping_ms_signed={client_ping_signed} "
                                                "decision=Sequential"
                                            )
                                            log(
                                                label,
                                                f"Waiting for NEW TGame TCP connection "
                                                f"to ZONE port {TGAME_ZONE_PORT}"
                                            )

                                        else:
                                            log(
                                                label,
                                                f"Unhandled GEO cmd=0x{app['cmd']:04x}"
                                            )

                                    elif app["magic"] == TGAME_ZN_MAGIC:
                                        # r11: make this live ZONE connection addressable by
                                        # UIN so A106/A112/A11A can be delivered to room peers.
                                        _v150_register_zone_session(
                                            role_state, conn, active_tgame_key, label
                                        )

                                        if app["cmd"] == TGAME_ZN_REQ_LOGIN:
                                            req = _v48_parse_zn_login(app["body"])
                                            log(
                                                label,
                                                "C2ZN_REQ_LOGIN: "
                                                f"sub=0x{req['sub_channel_id']:08x} "
                                                f"pref_crc=0x{req['preference_crc']:08x} "
                                                f"system_crc=0x{req['system_crc']:08x}"
                                            )

                                            base_seq = app["seq"]
                                            seq_login = (base_seq + 1) & 0xffffffff
                                            seq_pinfo = (base_seq + 2) & 0xffffffff
                                            seq_props = (base_seq + 3) & 0xffffffff
                                            seq_hints = (base_seq + 4) & 0xffffffff
                                            log(
                                                label,
                                                "TPDUFrame SEQ candidate ZONE: "
                                                f"client=0x{base_seq:08x} "
                                                f"login=0x{seq_login:08x} "
                                                f"pinfo=0x{seq_pinfo:08x} "
                                                f"props=0x{seq_props:08x} "
                                                f"hints=0x{seq_hints:08x}"
                                            )
                                            uin_now = _v150_role_uin(role_state)
                                            # Refresh cached profile values so persistent EXP
                                            # updates made before this login reach the client.
                                            _V140_PLAYER_STATE.reload(uin_now)
                                            persisted_nickname = PLAYER_DB.load_nickname(
                                                uin_now
                                            )
                                            awaiting_first_nickname = (
                                                persisted_nickname is None
                                            )
                                            role_state[
                                                "v5_awaiting_first_nickname"
                                            ] = awaiting_first_nickname

                                            # FIRST-NICKNAME-v20 controlled 0x0401 route test:
                                            # v19 proved that GfxMovie_Loading/TGameAction_Login
                                            # FName 0x12669(ErrorCode) routes ErrorCode 0x0401
                                            # into the stock CreateRole helper (FName 0x12C14).
                                            #
                                            # IMPORTANT: only a DB row whose nickname is still
                                            # NULL gets 0x0401. Existing accounts keep the proven
                                            # normal 0x8100 startup path.
                                            login_result = (
                                                0x0401 if awaiting_first_nickname
                                                else ZONE_ERR_SUCC
                                            )
                                            login_rsp = _v48_build_zn_login_response(
                                                seq_login,
                                                result=login_result,
                                                expose_wallet=not awaiting_first_nickname,
                                            )
                                            _v48_send_app(
                                                conn, active_tgame_key, login_rsp,
                                                label,
                                                "ZN2C_RES_LOGIN FIRST-NICKNAME-v20-FORCE-0401 "
                                                f"result=0x{login_result:04x} "
                                                f"uin={uin_now} "
                                                f"nickname={persisted_nickname!r}"
                                            )

                                            if awaiting_first_nickname:
                                                # v20 is deliberately NOT the normal FF05/profile
                                                # path. Do not publish A005/A006 even if an
                                                # unexpected FF05 appears; this keeps the test
                                                # isolated to A001.Result -> 129D5 -> 0x12669.
                                                role_state["v12_force_blank_nickname"] = True
                                                role_state["v13_no_role_login"] = True
                                                role_state["v20_force_a001_0401"] = True
                                                pending_zone_profile = None
                                                log(
                                                    "ACCOUNT",
                                                    "FIRST-NICKNAME-v20 FORCE-A001-0401 armed: "
                                                    f"uin={uin_now} result=0x0401 nickname=NULL; "
                                                    "A005/A006 profile intentionally withheld; "
                                                    "expected client route: 129D5 -> 0x12669(0x0401) "
                                                    "-> 0x12C14 CreateRole helper",
                                                )
                                            else:
                                                role_state.pop("v12_force_blank_nickname", None)
                                                role_state.pop("v13_no_role_login", None)
                                                # Existing accounts keep the proven normal path:
                                                # wait for FF05, then publish the full profile.
                                                pending_zone_profile = {
                                                    "seq_pinfo": seq_pinfo,
                                                    "seq_props": seq_props,
                                                    "seq_hints": seq_hints,
                                                    "first_nickname_probe": False,
                                                }
                                                log(
                                                    label,
                                                    "v71: profile notifications DEFERRED until "
                                                    "client FF05 readiness packet"
                                                )

                                        elif app["cmd"] == 0xFF05:
                                            ff05_value = (
                                                struct.unpack(">I", app["body"][:4])[0]
                                                if len(app["body"]) >= 4 else None
                                            )
                                            log(
                                                label,
                                                "C2ZN FF05 observed: "
                                                + (f"value=0x{ff05_value:08x} ({ff05_value}) " if ff05_value is not None else "")
                                                + "=> client login-ready milestone"
                                            )

                                            if pending_zone_profile is not None:
                                                first_nickname_profile = bool(
                                                    pending_zone_profile.get(
                                                        "first_nickname_probe", False
                                                    )
                                                )
                                                profile_nickname = (
                                                    "" if first_nickname_profile
                                                    else _v150_role_nickname(role_state)
                                                )
                                                if first_nickname_profile:
                                                    log(
                                                        "ACCOUNT",
                                                        "FIRST-NICKNAME-v11 FF05 reached; publishing "
                                                        "complete normal profile with NickName='' "
                                                        "instead of withholding A006/hints",
                                                    )

                                                # v121: natural stock self-heal test.
                                                # Start with CurRoleGID=0 so the client is
                                                # unambiguously in the "current role invalid"
                                                # state when the Chief PropInfo arrives in A006.
                                                # The PH client contains a native
                                                # HandleMessage_Notification_PropInfo ->
                                                # ReSetCurrentRole path for exactly this case.
                                                pinfo = _v48_build_playerinfo(
                                                    pending_zone_profile["seq_pinfo"],
                                                    uin=_v150_role_uin(role_state),
                                                    cur_role_gid=0,
                                                    nickname=profile_nickname,
                                                )
                                                _v48_send_app(
                                                    conn, active_tgame_key, pinfo,
                                                    label,
                                                    "ZN2C_NTF_PLAYERINFO v121-pre-props "
                                                    f"experience={int(V140_MALL_STATE.get('experience', 0))} "
                                                    "CurRoleGID=0 natural-selfheal-arm"
                                                )

                                                # v140: preserve v129's proven starter group ordering,
                                                # then append persistent mall purchases in legal
                                                # PropInfo[5] chunks.  This allows a character bought
                                                # in Mall to survive restart and be available to the
                                                # normal CurrentRole/PreviewRole logic.
                                                login_groups = (
                                                    _v13_login_prop_groups_no_roles()
                                                    if first_nickname_profile
                                                    else _v140_login_prop_groups()
                                                )
                                                for group_index, group in enumerate(login_groups):
                                                    is_last = group_index == len(login_groups) - 1
                                                    props_pkt = _v127_build_playerprops_chunk(
                                                        group,
                                                        is_last,
                                                        session_uin=_v150_role_uin(role_state),
                                                    )
                                                    _v48_send_app(
                                                        conn, active_tgame_key,
                                                        props_pkt, label,
                                                        "ZN2C_NTF_PLAYERPROPS v140-login "
                                                        f"chunk={group_index+1}/{len(login_groups)} "
                                                        f"is_last={int(is_last)} "
                                                        f"prop_count={len(group)}",
                                                    )

                                                # v121 natural current-role self-heal sequence:
                                                #
                                                # Live v44 proves UTGOnlinePlayerData.CurrentRolePropId
                                                # remains zero even though the initial A005 carries
                                                # CurRoleGID=V109_ROLE_GID and A006 later supplies the
                                                # matching Chief PropInfo.  Re-publish PlayerInfo only
                                                # AFTER the PropInfo stream has completed so the stock
                                                # client can resolve CurRoleGID against an already-known
                                                # role prop.
                                                #
                                                # This is intentionally A005-only.  Do NOT add another
                                                # full A006 snapshot here; v117 removed post-operation
                                                # A006 refreshes because they rebuild the Storage bag UI.
                                                pinfo_after_props = _v48_build_playerinfo(
                                                    0,
                                                    uin=_v150_role_uin(role_state),
                                                    cur_role_gid=(
                                                        0
                                                        if first_nickname_profile
                                                        else _r13_wire_current_role_gid(
                                                            _v150_role_uin(role_state)
                                                        )
                                                    ),
                                                    nickname=profile_nickname,
                                                )
                                                _v48_send_app(
                                                    conn, active_tgame_key,
                                                    pinfo_after_props,
                                                    label,
                                                    "ZN2C_NTF_PLAYERINFO v121-after-props "
                                                    f"experience={int(V140_MALL_STATE.get('experience', 0))} "
                                                    + (
                                                        "CurRoleGID=0 FIRST-NICKNAME-v13-no-role "
                                                        if first_nickname_profile
                                                        else f"CurRoleGID=0x{_v140_current_role_gid():016x} "
                                                    )
                                                    + "reason=current-role-resolve-after-A006"
                                                )

                                                _v140_send_wallet_sync(
                                                    conn,
                                                    active_tgame_key,
                                                    label,
                                                    reason=UPDATE_REASON_TP_BALANCE,
                                                    prefix="login",
                                                )
                                                _v140_send_experience_sync(
                                                    conn,
                                                    active_tgame_key,
                                                    label,
                                                )

                                                # Existing profiles receive their newest
                                                # durable Consumer List rows after A005/A006
                                                # and wallet/EXP state are established.
                                                if not first_nickname_profile:
                                                    _v140_replay_moneyflow(
                                                        conn,
                                                        active_tgame_key,
                                                        label,
                                                        session_uin=_v150_role_uin(
                                                            role_state
                                                        ),
                                                    )

                                                hints = _v48_build_zonehints(
                                                    pending_zone_profile["seq_hints"]
                                                )
                                                _v48_send_app(
                                                    conn, active_tgame_key, hints,
                                                    label,
                                                    "ZN2C_NTF_ZONE_HINTS v71-after-ff05 "
                                                    "hint=0"
                                                )

                                                resume_room = role_state.pop(
                                                    "persistent_resume_room", None
                                                )
                                                if isinstance(resume_room, dict):
                                                    room_rsp = _v150_build_res_enter_match_room(
                                                        resume_room
                                                    )
                                                    _v48_send_app(
                                                        conn,
                                                        active_tgame_key,
                                                        room_rsp,
                                                        label,
                                                        "ZN2C_RES_ENTERMATCHROOM persistent-resume "
                                                        f"room={int(resume_room['room_id'])}",
                                                    )
                                                    log(
                                                        label,
                                                        "Persistent TGame lobby room replayed "
                                                        f"uin={_v150_role_uin(role_state)} "
                                                        f"room={int(resume_room['room_id'])}",
                                                    )

                                                pending_zone_profile = None
                                                if first_nickname_profile:
                                                    log(
                                                        "ACCOUNT",
                                                        "FIRST-NICKNAME-v12 full sticky-empty-nickname profile "
                                                        "published; startup may now complete; waiting "
                                                        "for stock A144/A002 or lobby transition",
                                                    )
                                                log(
                                                    label,
                                                    "v71: deferred profile sequence sent "
                                                    "after FF05"
                                                )
                                            else:
                                                log(
                                                    label,
                                                    "v71: FF05 received with no pending "
                                                    "profile sequence"
                                                )

                                        elif app["cmd"] == TGAME_ZN_REQ_SHOPCONFHASH:
                                            client_hash = _v140_parse_shop_conf_hash(
                                                app["body"]
                                            )
                                            log(
                                                label,
                                                f"C2ZN_REQ_SHOPCONFHASH v140 "
                                                f"client_hash=0x{client_hash:08x}",
                                            )
                                            rsp = _v140_build_shop_conf_hash_response(
                                                client_hash
                                            )
                                            _v48_send_app(
                                                conn,
                                                active_tgame_key,
                                                rsp,
                                                label,
                                                "ZN2C_RES_SHOPCONFHASH v140 "
                                                "cmd=0xA362 result=0x8200 "
                                                "server_hash=echo url=''",
                                            )

                                        elif app["cmd"] == TGAME_ZN_REQ_UPDATECOMMODITYFILE:
                                            file_id = (
                                                struct.unpack(">I", app["body"])[0]
                                                if len(app["body"]) == 4
                                                else None
                                            )
                                            log(
                                                label,
                                                "C2ZN_REQ_UPDATECOMMODITYFILE v140 "
                                                f"body={app['body'].hex()} "
                                                f"file_id={file_id}",
                                            )
                                            rsp = _v140_build_update_commodity_response()
                                            _v48_send_app(
                                                conn,
                                                active_tgame_key,
                                                rsp,
                                                label,
                                                "ZN2C_RES_UPDATECOMMODITYFILE v140 "
                                                "cmd=0xA504 result=0x8200",
                                            )

                                        elif app["cmd"] == TGAME_ZN_REQ_TP_BALANCE:
                                            # AP-NATIVE-REFRESH-v1:
                                            # Website/DB changes are external to this process,
                                            # so A50E is the explicit cache-refresh boundary.
                                            if len(app["body"]) != 8:
                                                raise ValueError(
                                                    "A50E TP/AP balance request must be 8B"
                                                )
                                            balance_uin = struct.unpack(
                                                ">Q", app["body"]
                                            )[0]
                                            session_uin = int(
                                                _v150_role_uin(role_state)
                                            )
                                            if int(balance_uin) != session_uin:
                                                log(
                                                    label,
                                                    "C2ZN_REQ_TPBALANCE "
                                                    "WALLET-NATIVE-REFRESH-v2 "
                                                    f"wire_uin={balance_uin} "
                                                    f"session_uin={session_uin} "
                                                    "action=USE_AUTHENTICATED_UIN",
                                                )

                                            # Reload the authoritative persisted wallet.
                                            # This makes an AP value changed by the website
                                            # visible without reconnecting the player.
                                            _V140_PLAYER_STATE.reload(session_uin)
                                            wallet = _v140_wallet()

                                            log(
                                                label,
                                                "C2ZN_REQ_TPBALANCE "
                                                "AP-NATIVE-REFRESH-v1 "
                                                f"uin={session_uin} "
                                                f"AP={wallet['ap']} "
                                                "action=SQLITE_RELOAD_NATIVE_A00A_AP_GP_MP",
                                            )

                                            # The stock AP reload click is our explicit
                                            # authoritative wallet refresh boundary.  AP,
                                            # GP and MP are independent bitmask updates; do
                                            # not mutate the wallet here.
                                            for (
                                                refresh_flag,
                                                refresh_name,
                                                refresh_reason,
                                                pkt,
                                            ) in _v140_build_authoritative_wallet_refresh():
                                                _v48_send_app(
                                                    conn,
                                                    active_tgame_key,
                                                    pkt,
                                                    label,
                                                    "ZN2C_NTF_UPDATEPLAYERPROPERTY "
                                                    "WALLET-NATIVE-REFRESH-v2 "
                                                    f"cmd=0xA00A flag={refresh_name} "
                                                    f"flag_value=0x{refresh_flag:02X} "
                                                    f"reason=0x{refresh_reason:02X} "
                                                    f"uin={session_uin} "
                                                    f"AP={wallet['ap']} "
                                                    f"GP={wallet['gp']} "
                                                    f"MP={wallet['mp']}",
                                                )

                                        elif app["cmd"] == TGAME_ZN_REQ_BUYCOMMODITY:
                                            req = _v140_parse_buy_commodity(
                                                app["body"]
                                            )
                                            log(
                                                label,
                                                "C2ZN_REQ_BUYCOMMODITY v140 "
                                                f"buy_type={req['buy_type']} "
                                                f"pay_type={req['pay_type']} "
                                                f"count={req['count']} "
                                                f"commodities="
                                                f"{[(x['commodity_id'], x['price_index'], x['client_price']) for x in req['commodities']]}",
                                            )

                                            try:
                                                plan = _v140_plan_purchase(
                                                    req,
                                                    self_uin=_v150_role_uin(role_state),
                                                )
                                            except _v140_ShopReject as reject:
                                                log(
                                                    "MALL",
                                                    f"v140 purchase rejected "
                                                    f"result=0x{reject.result:04x} "
                                                    f"reason={reject.message}",
                                                )
                                                rsp = _v140_build_buy_response(
                                                    req,
                                                    [],
                                                    result=reject.result,
                                                    self_uin=_v150_role_uin(role_state),
                                                )
                                                _v48_send_app(
                                                    conn,
                                                    active_tgame_key,
                                                    rsp,
                                                    label,
                                                    "ZN2C_RES_BUYCOMMODITY v140 "
                                                    f"REJECT result=0x{reject.result:04x}",
                                                )
                                            else:
                                                all_new_props = []
                                                for row in plan["staged"]:
                                                    all_new_props.extend(row["props"])

                                                # Atomic commit point.
                                                V111_INVENTORY.extend(
                                                    dict(p) for p in all_new_props
                                                )
                                                wallet = _v140_wallet()
                                                wallet["ap"] -= int(plan["consume_tp"])
                                                wallet["gp"] -= int(plan["consume_gp"])
                                                wallet["mp"] -= int(plan["consume_mp"])

                                                purchase_uin = _v150_role_uin(
                                                    role_state
                                                )
                                                purchase_time = int(time.time())
                                                purchase_details = "; ".join(
                                                    str(row.get("commodity_name", ""))
                                                    for row in plan["staged"]
                                                    if str(row.get("commodity_name", ""))
                                                )
                                                purchase_commodity_ids = [
                                                    int(row["commodity_id"])
                                                    for row in plan["staged"]
                                                ]
                                                purchase_moneyflow_rows = (
                                                    _v140_make_purchase_moneyflow_rows(
                                                        session_uin=purchase_uin,
                                                        consume_tp=plan["consume_tp"],
                                                        consume_gp=plan["consume_gp"],
                                                        consume_mp=plan["consume_mp"],
                                                        occurred_at=purchase_time,
                                                        details=purchase_details,
                                                        commodity_ids=purchase_commodity_ids,
                                                    )
                                                )

                                                # Wallet, inventory and Consumer List rows
                                                # become durable in one SQLite transaction.
                                                _v140_save_state(
                                                    "buy",
                                                    moneyflow_rows=purchase_moneyflow_rows,
                                                )

                                                rsp = _v140_build_buy_response(
                                                    req,
                                                    plan["staged"],
                                                    result=SHOP_ERR_SUCC,
                                                    consume_tp=plan["consume_tp"],
                                                    consume_gp=plan["consume_gp"],
                                                    consume_mp=plan["consume_mp"],
                                                    self_uin=_v150_role_uin(role_state),
                                                )
                                                _v48_send_app(
                                                    conn,
                                                    active_tgame_key,
                                                    rsp,
                                                    label,
                                                    "ZN2C_RES_BUYCOMMODITY v140 "
                                                    "cmd=0xA506 result=0x8200 "
                                                    f"new_props={len(all_new_props)}",
                                                )

                                                _v140_send_wallet_sync(
                                                    conn,
                                                    active_tgame_key,
                                                    label,
                                                    reason=UPDATE_REASON_BUY,
                                                    prefix="post-buy",
                                                )

                                                # Issue #42: publish the exact rows that were
                                                # committed with the purchase transaction.
                                                _v140_send_moneyflow_rows(
                                                    conn,
                                                    active_tgame_key,
                                                    label,
                                                    purchase_moneyflow_rows,
                                                    source="live-buy",
                                                )

                                                # Publish the newly authoritative inventory.
                                                # Buy response itself carries bought PropIds;
                                                # A006 makes the normal Storage/Avatar queries
                                                # see those same props immediately.
                                                _v140_send_full_inventory(
                                                    conn,
                                                    active_tgame_key,
                                                    label,
                                                    prefix="post-buy",
                                                    session_uin=_v150_role_uin(role_state),
                                                )

                                                # Re-publish the selected role only after the
                                                # purchased props are known to the client.
                                                pinfo = _v48_build_playerinfo(
                                                    0,
                                                    uin=_v150_role_uin(role_state),
                                                    cur_role_gid=_r13_wire_current_role_gid(
                                                        _v150_role_uin(role_state)
                                                    ),
                                                    nickname=_v150_role_nickname(role_state),
                                                )
                                                _v48_send_app(
                                                    conn,
                                                    active_tgame_key,
                                                    pinfo,
                                                    label,
                                                    "ZN2C_NTF_PLAYERINFO v140 post-buy "
                                                    f"CurRoleGID=0x{_v140_current_role_gid():016x}",
                                                )

                                                log(
                                                    "MALL",
                                                    "v140 purchase committed: "
                                                    + "; ".join(
                                                        f"{row['commodity_id']}:{row['commodity_name']!r} "
                                                        f"items={[p['item_id'] for p in row['props']]}"
                                                        for row in plan["staged"]
                                                    )
                                                    + f" | wallet AP={wallet['ap']} "
                                                    f"GP={wallet['gp']} MP={wallet['mp']}",
                                                )

                                        elif app["cmd"] == TGAME_ZN_REQ_ITEM_OPERATION:
                                            wire_op = _v111_parse_prop_operation(
                                                app["body"]
                                            )
                                            session_uin = _v150_role_uin(role_state)
                                            op = _r13_canonicalize_operation(
                                                wire_op, session_uin
                                            )
                                            action, effective_op = _v111_apply_prop_operation(
                                                op
                                            )
                                            effective_body = _v111_pack_prop_operation(
                                                _r13_project_operation(
                                                    effective_op, session_uin
                                                )
                                            )
                                            _v140_save_state("A200-item-operation")
                                            rsp = _v140_build_item_operation_response(
                                                effective_body
                                            )
                                            _v48_send_app(
                                                conn,
                                                active_tgame_key,
                                                rsp,
                                                label,
                                                "ZN2C_RES_ITEM_OPERATION v160 "
                                                "cmd=0xA201 result=0x8100",
                                            )
                                            _v140_send_full_inventory(
                                                conn,
                                                active_tgame_key,
                                                label,
                                                prefix="v160-item-operation",
                                                session_uin=session_uin,
                                            )
                                            log(
                                                "MALL",
                                                "v160 A200 item operation => "
                                                f"{action}; authoritative A006 refreshed",
                                            )

                                        elif app["cmd"] == TGAME_ZN_REQ_PROP_OPERATION:
                                            wire_op = _v111_parse_prop_operation(
                                                app["body"]
                                            )
                                            session_uin = _v150_role_uin(role_state)
                                            op = _r13_canonicalize_operation(
                                                wire_op, session_uin
                                            )

                                            # v165: preserve the subject's pre-operation
                                            # ownership before _v111_apply_prop_operation()
                                            # mutates it. This lets us dynamically identify
                                            # root-level equipment TAKEOFF as well as EQUIP
                                            # without knowing any item IDs.
                                            _v165_pre_subject = _v140_find_prop(
                                                int(op.get("subject_gid", 0))
                                            )
                                            _v165_pre_item_id = (
                                                int(
                                                    _v165_pre_subject.get(
                                                        "item_id", 0
                                                    )
                                                )
                                                if _v165_pre_subject is not None
                                                else 0
                                            )
                                            _v165_pre_owner = (
                                                int(
                                                    _v165_pre_subject.get(
                                                        "owner_gid", 0
                                                    )
                                                )
                                                if _v165_pre_subject is not None
                                                else 0
                                            )

                                            action, effective_op = (
                                                _v111_apply_prop_operation(op)
                                            )
                                            effective_body = (
                                                _v111_pack_prop_operation(
                                                    _r13_project_operation(
                                                        effective_op, session_uin
                                                    )
                                                )
                                            )
                                            log(
                                                label,
                                                "C2ZN_REQ_PROPOPERATION v140: "
                                                f"op={wire_op['operation']} "
                                                f"subject=0x{wire_op['subject_gid']:016x} "
                                                f"client_target=0x{wire_op['target_gid']:016x} "
                                                f"client_loc=0x{wire_op['location']:02x} "
                                                f"=> {action}"
                                            )
                                            _v140_save_state("A008-prop-operation")
                                            log(
                                                "MALL",
                                                "v141 bag invariant "
                                                f"current_bag=0x{_v141_current_bag_gid():016x} "
                                                f"current_role=0x{_v140_current_role_gid():016x} "
                                                + _v141_bag_invariant_text()
                                            )

                                            rsp = (
                                                _v111_build_prop_operation_response(
                                                    effective_body
                                                )
                                            )
                                            _v48_send_app(
                                                conn, active_tgame_key, rsp,
                                                label,
                                                "ZN2C_RES_PROPOPERATION v117 "
                                                "cmd=0xA009 result=0x8100 "
                                                "+ authoritative operation"
                                            )

                                            ntf = (
                                                _v111_build_prop_operation_notification(
                                                    effective_body
                                                )
                                            )
                                            _v48_send_app(
                                                conn, active_tgame_key, ntf,
                                                label,
                                                "ZN2C_NTF_PROPOPERATION v117 "
                                                "cmd=0xA00A authoritative operation"
                                            )

                                            # v117:
                                            # Do NOT send a full A006 PlayerProps snapshot
                                            # after each A008 operation.
                                            #
                                            # The stock client already receives the
                                            # authoritative operation through A009 + A00A.
                                            # Re-sending the complete PlayerProps list here
                                            # causes the Storage UI to rebuild its bag view;
                                            # in the live PH client that can snap the visible
                                            # selection to the stale CurrentBag value (the
                                            # observed Bag1 -> Bag2 jump immediately after
                                            # equipping QBS09).
                                            #
                                            # Initial login still sends the normal A006
                                            # profile snapshot.  We only suppress this
                                            # redundant post-operation refresh.
                                            log(
                                                label,
                                                "v117 inventory after A008 (A009+A00A only; "
                                                "full A006 refresh suppressed): "
                                                + _v111_inventory_summary()
                                            )

                                            # v142: v144 live-memory tracing proved that A009+A00A
                                            # alone does NOT update TGOnlinePlayerData.CurrentBagPropId
                                            # for an explicit bag selection. Keep v117's
                                            # suppression for roles/weapons, but for a BAG selection
                                            # publish the authoritative inventory immediately after
                                            # A009+A00A so the stock client can rebuild CurrentBag.
                                            #
                                            # This is intentionally scoped to bag subjects only;
                                            # sending A006 after every A008 previously caused weapon
                                            # equip operations to rebuild/snap the Storage bag view.
                                            _v142_subject = _v140_find_prop(
                                                int(op.get("subject_gid", 0))
                                            )
                                            _v142_item_id = (
                                                int(_v142_subject.get("item_id", 0))
                                                if _v142_subject is not None
                                                else 0
                                            )

                                            # v165: root-level equipment changes can invalidate
                                            # the stock Storage Weapon-tab cache even though the
                                            # authoritative current bag and weapon ownership are
                                            # still correct.
                                            #
                                            # Detect the CLASS of operation, not any specific
                                            # item/bag:
                                            #   - EQUIP or TAKEOFF
                                            #   - real known subject
                                            #   - not a character root
                                            #   - not a backpack
                                            #   - subject was or becomes attached to root owner 1
                                            #
                                            # Weapon changes remain excluded because their owner
                                            # is a dynamic backpack GID, preserving v117's proven
                                            # no-A006 behavior for weapon-slot operations.
                                            _v165_root_equipment_change = (
                                                _v165_pre_subject is not None
                                                and int(
                                                    op.get("operation", -1)
                                                )
                                                in (
                                                    PROP_OP_EQUIP,
                                                    PROP_OP_TAKEOFF,
                                                )
                                                and not _v140_is_role_item(
                                                    _v165_pre_item_id
                                                )
                                                and not _v141_is_bag_item(
                                                    _v165_pre_item_id
                                                )
                                                and (
                                                    int(_v165_pre_owner)
                                                    == V110_BAG_MOUNT_OWNER
                                                    or int(
                                                        effective_op.get(
                                                            "target_gid", 0
                                                        )
                                                    )
                                                    == V110_BAG_MOUNT_OWNER
                                                )
                                            )

                                            if _v165_root_equipment_change:
                                                _v165_bag_gid = (
                                                    _v141_current_bag_gid()
                                                )
                                                _v165_bag = _v140_find_prop(
                                                    _v165_bag_gid
                                                )

                                                if (
                                                    _v165_bag is not None
                                                    and _v141_is_bag_item(
                                                        int(
                                                            _v165_bag.get(
                                                                "item_id", 0
                                                            )
                                                        )
                                                    )
                                                ):
                                                    _v165_bag_body = (
                                                        _v111_pack_prop_operation(
                                                            _r13_project_operation(
                                                                {
                                                                    "operation": PROP_OP_EQUIP,
                                                                    "subject_gid": _v165_bag_gid,
                                                                    "target_gid": V110_BAG_MOUNT_OWNER,
                                                                    "location": V109_LOC_BAG,
                                                                },
                                                                session_uin,
                                                            )
                                                        )
                                                    )

                                                    _v48_send_app(
                                                        conn,
                                                        active_tgame_key,
                                                        _v111_build_prop_operation_response(
                                                            _v165_bag_body
                                                        ),
                                                        label,
                                                        "ZN2C_RES_PROPOPERATION "
                                                        "v165-root-item-current-bag "
                                                        "cmd=0xA009 result=0x8100 "
                                                        f"bag=0x{_v165_bag_gid:016x}",
                                                    )
                                                    _v48_send_app(
                                                        conn,
                                                        active_tgame_key,
                                                        _v111_build_prop_operation_notification(
                                                            _v165_bag_body
                                                        ),
                                                        label,
                                                        "ZN2C_NTF_PROPOPERATION "
                                                        "v165-root-item-current-bag "
                                                        "cmd=0xA00A "
                                                        f"bag=0x{_v165_bag_gid:016x}",
                                                    )
                                                    _v140_send_full_inventory(
                                                        conn,
                                                        active_tgame_key,
                                                        label,
                                                        prefix=(
                                                            "v165-root-item-bag-reconcile"
                                                        ),
                                                        session_uin=session_uin,
                                                    )
                                                    log(
                                                        label,
                                                        "v165: dynamic root-equipment "
                                                        "change reconciled selected bag + A006 "
                                                        f"item={_v165_pre_item_id} "
                                                        f"op={int(op.get('operation', -1))} "
                                                        f"pre_owner=0x{int(_v165_pre_owner):016x} "
                                                        f"post_owner=0x{int(effective_op.get('target_gid', 0)):016x} "
                                                        f"bag=0x{_v165_bag_gid:016x}",
                                                    )
                                                else:
                                                    log(
                                                        label,
                                                        "v165: root-equipment reconcile "
                                                        "skipped: current bag does not resolve "
                                                        "to an owned backpack "
                                                        f"bag=0x{int(_v165_bag_gid):016x}",
                                                    )

                                            if (
                                                int(op.get("operation", -1)) == PROP_OP_EQUIP
                                                and _v141_is_bag_item(_v142_item_id)
                                            ):
                                                _v140_send_full_inventory(
                                                    conn,
                                                    active_tgame_key,
                                                    label,
                                                    prefix="v142-bag-select-sync",
                                                    session_uin=session_uin,
                                                )
                                                log(
                                                    label,
                                                    "v142: bag-select A009+A00A completed; "
                                                    "sent legal chunked A006 inventory sync "
                                                    f"subject=0x{int(op.get('subject_gid',0)):016x} "
                                                    f"item={_v142_item_id} "
                                                    f"current_bag=0x{_v141_current_bag_gid():016x}",
                                                )

                                                # v157b: explicit Storage bag state must be
                                                # republished after the lobby rebuilds.
                                                role_state[
                                                    "v157_storage_bag_resync_pending"
                                                ] = True
                                                role_state[
                                                    "v157_storage_bag_resync_mainchan_base"
                                                ] = int(
                                                    role_state.get(
                                                        "v125_mainchan_count", 0
                                                    )
                                                )
                                                role_state[
                                                    "v157_storage_bag_resync_a303_base"
                                                ] = int(
                                                    role_state.get(
                                                        "v125_a303_count", 0
                                                    )
                                                )
                                                role_state[
                                                    "v125_bag1_refresh_armed"
                                                ] = False
                                                log(
                                                    label,
                                                    "v157b: explicit bag selection armed "
                                                    "Storage->lobby resync "
                                                    f"bag=0x{_v141_current_bag_gid():016x} "
                                                    f"mainchan_base={int(role_state.get('v157_storage_bag_resync_mainchan_base', 0))} "
                                                    f"a303_base={int(role_state.get('v157_storage_bag_resync_a303_base', 0))}",
                                                )

                                            # v125: DO NOT refresh Bag1 here.
                                            #
                                            # v124 proved this point is still too early: the Chief
                                            # transaction completes before the lobby/main-channel
                                            # UI has initialized, so an A00A sent here is consumed
                                            # without fixing the visible Bag1 weapon slot.
                                            #
                                            # Preserve v122's proven A005 role commit, then merely
                                            # arm the Bag1 refresh.  We fire it later when A303
                                            # proves the stock lobby/social UI is alive.
                                            _v140_role_subject = _v140_find_prop(
                                                int(op.get("subject_gid", 0))
                                            )
                                            _v140_role_slot_value = (
                                                _v140_role_slot(
                                                    int(_v140_role_subject.get("item_id", 0))
                                                )
                                                if _v140_role_subject is not None
                                                else None
                                            )
                                            if (
                                                int(op.get("operation", -1)) == PROP_OP_EQUIP
                                                and _v140_role_subject is not None
                                                and _v140_role_slot_value in (0x0A, 0x0B)
                                                and int(effective_op.get("location", -1)) == _v140_role_slot_value
                                            ):
                                                pinfo_role_committed = _v48_build_playerinfo(
                                                    0,
                                                    uin=session_uin,
                                                    cur_role_gid=_r13_wire_current_role_gid(
                                                        session_uin
                                                    ),
                                                    nickname=_v150_role_nickname(role_state),
                                                )
                                                _v48_send_app(
                                                    conn, active_tgame_key,
                                                    pinfo_role_committed, label,
                                                    "ZN2C_NTF_PLAYERINFO v140-post-role-A00A "
                                                    f"CurRoleGID=0x{_v140_current_role_gid():016x} "
                                                    f"experience={int(V140_MALL_STATE.get('experience', 0))} "
                                                    "reason=role-equip-transaction-complete",
                                                )
                                                # v167: a stock role switch invalidates the
                                                # Storage Weapon-tab contents cache.  The backend
                                                # state remains correct (selected backpack and its
                                                # weapon ownership do not change), but an A00A-only
                                                # backpack replay is insufficient: the UI shows the
                                                # selected bag with empty weapon slots until the user
                                                # clicks that same bag again.
                                                #
                                                # Reconcile the ACTUAL selected backpack
                                                # dynamically.  No Bag1/Bag2 GID, role, weapon or
                                                # item ID is hard-coded:
                                                #   role A008/A009/A00A
                                                #     -> A005 current role
                                                #     -> A00A current backpack
                                                #     -> authoritative A006 inventory snapshot
                                                #
                                                # This intentionally remains role-switch scoped.
                                                # v117's no-A006 rule for ordinary weapon A008
                                                # operations is left unchanged.
                                                _v167_bag_gid = _v141_current_bag_gid()
                                                _v167_bag = _v140_find_prop(_v167_bag_gid)
                                                if (
                                                    _v167_bag is not None
                                                    and _v141_is_bag_item(
                                                        int(
                                                            _v167_bag.get(
                                                                "item_id", 0
                                                            )
                                                        )
                                                    )
                                                ):
                                                    _v167_bag_body = (
                                                        _v111_pack_prop_operation(
                                                            _r13_project_operation(
                                                                {
                                                                    "operation": PROP_OP_EQUIP,
                                                                    "subject_gid": _v167_bag_gid,
                                                                    "target_gid": V110_BAG_MOUNT_OWNER,
                                                                    "location": V109_LOC_BAG,
                                                                },
                                                                session_uin,
                                                            )
                                                        )
                                                    )
                                                    # v168: v167 proved that A00A + A006 alone is
                                                    # not enough after a role switch.  The already-
                                                    # proven v165 Item-tab fix and a real manual bag
                                                    # click both use the complete stock callback
                                                    # sequence A009 -> A00A -> A006.  Reuse that
                                                    # sequence here for the dynamically selected bag.
                                                    #
                                                    # A009 is intentionally emitted before A00A,
                                                    # matching the normal A008 bag-selection handler.
                                                    # Backend ownership is NOT changed here.
                                                    _v168_bag_rsp = (
                                                        _v111_build_prop_operation_response(
                                                            _v167_bag_body
                                                        )
                                                    )
                                                    _v168_bag_ntf = (
                                                        _v111_build_prop_operation_notification(
                                                            _v167_bag_body
                                                        )
                                                    )
                                                    _v48_send_app(
                                                        conn,
                                                        active_tgame_key,
                                                        _v168_bag_rsp,
                                                        label,
                                                        "ZN2C_RES_PROPOPERATION "
                                                        "v168-post-role-current-bag "
                                                        "cmd=0xA009 result=0x8100 "
                                                        f"bag=0x{_v167_bag_gid:016x}",
                                                    )
                                                    _v48_send_app(
                                                        conn,
                                                        active_tgame_key,
                                                        _v168_bag_ntf,
                                                        label,
                                                        "ZN2C_NTF_PROPOPERATION "
                                                        "v168-post-role-current-bag "
                                                        "cmd=0xA00A "
                                                        f"bag=0x{_v167_bag_gid:016x}",
                                                    )
                                                    _v140_send_full_inventory(
                                                        conn,
                                                        active_tgame_key,
                                                        label,
                                                        prefix=(
                                                            "v168-post-role-bag-reconcile"
                                                        ),
                                                        session_uin=session_uin,
                                                    )
                                                    log(
                                                        label,
                                                        "v168: role switch replayed complete "
                                                        "dynamic bag callback A009+A00A+A006 "
                                                        f"bag=0x{_v167_bag_gid:016x} "
                                                        f"bag_item={int(_v167_bag.get('item_id', 0))}",
                                                    )
                                                else:
                                                    log(
                                                        label,
                                                        "v167: post-role bag reconcile "
                                                        "skipped because current bag does not "
                                                        "resolve to an owned backpack "
                                                        f"bag=0x{int(_v167_bag_gid):016x}",
                                                    )
                                                # Keep the old Bag1 refresh compatibility only for
                                                # the starter role; purchased roles do not need to arm
                                                # that historical startup workaround.
                                                if int(_v140_role_subject.get("gid", 0)) == V109_ROLE_GID:
                                                    role_state["v125_bag1_refresh_armed"] = True
                                                    role_state["v125_chief_committed"] = True
                                                log(
                                                    label,
                                                    "v140: current role committed through stock A008/A009/A00A "
                                                    f"gid=0x{_v140_current_role_gid():016x} "
                                                    f"item={int(_v140_role_subject.get('item_id',0))}"
                                                )

                                        elif app["cmd"] in CLAN_COMMANDS:
                                            _clan_dispatch(conn, active_tgame_key, app, tgame_session_uin, label)

                                        elif app["cmd"] == TGAME_ZN_REQ_CHECK_NICKNAME:
                                            nick = None
                                            try:
                                                nick = _v5_parse_first_nickname(
                                                    app["body"]
                                                )
                                                ok, normalized_nick, reason = (
                                                    _v5_validate_first_nickname(nick)
                                                )
                                            except Exception as nick_e:
                                                ok = False
                                                normalized_nick = ""
                                                reason = f"parse:{nick_e}"

                                            uin_now = _v150_role_uin(role_state)
                                            available = False
                                            if ok:
                                                try:
                                                    available = PLAYER_DB.nickname_available(
                                                        normalized_nick,
                                                        exclude_uin=uin_now,
                                                    )
                                                except Exception as nick_db_e:
                                                    reason = (
                                                        "db:"
                                                        f"{type(nick_db_e).__name__}:"
                                                        f"{nick_db_e}"
                                                    )
                                                    log(
                                                        "ACCOUNT",
                                                        "FIRST-NICKNAME-v26 A144 "
                                                        "availability DB failure: "
                                                        f"uin={uin_now} "
                                                        f"{type(nick_db_e).__name__}: "
                                                        f"{nick_db_e}",
                                                    )
                                            if str(reason).startswith("db:"):
                                                result = ZONE_FAIL_SERVER_BUSY
                                            elif not ok:
                                                result = ZONE_FAIL_ILLEGAL_NICKNAME
                                            elif available:
                                                result = ZONE_ERR_SUCC
                                            else:
                                                result = ZONE_FAIL_NICKNAME_EXIST
                                            log(
                                                "ACCOUNT",
                                                "FIRST-NICKNAME-v26f A144 CheckNickName "
                                                f"uin={uin_now} nick={nick!r} "
                                                f"valid={ok} available={available} "
                                                f"reason={reason}",
                                            )
                                            rsp = _v5_build_check_nickname_response(
                                                result
                                            )
                                            _v48_send_app(
                                                conn,
                                                active_tgame_key,
                                                rsp,
                                                label,
                                                "ZN2C_RES_CHECKNICKNAME first-nickname-v26f "
                                                f"cmd=0xA145 result=0x{result:04x} "
                                                f"available={available}",
                                            )

                                        elif app["cmd"] == TGAME_ZN_REQ_CURR_ONLINE_TIME:
                                            log(
                                                label,
                                                "C2ZN_REQ_CURRONLINETIME FIRST-NICKNAME-v6 "
                                                "(0xC119) "
                                                f"body={app['body'].hex()}"
                                            )
                                            rsp = _v6_build_curr_online_time_response(
                                                (app["seq"] + 1) & 0xffffffff,
                                                seconds=0,
                                            )
                                            _v48_send_app(
                                                conn,
                                                active_tgame_key,
                                                rsp,
                                                label,
                                                "ZN2C_RES_CURRONLINETIME FIRST-NICKNAME-v6 "
                                                "cmd=0xC11A CurrOnlineTime=0",
                                            )
                                            if role_state.get(
                                                "v5_awaiting_first_nickname"
                                            ):
                                                log(
                                                    "ACCOUNT",
                                                    "FIRST-NICKNAME-v12 C119 observed; nickname "
                                                    "still NULL; full empty-nickname profile was "
                                                    "already published after FF05; waiting for "
                                                    "next stock client request",
                                                )

                                        elif app["cmd"] == TGAME_ZN_REQ_HEARTBEAT:
                                            hb_seq = (app["seq"] + 1) & 0xffffffff
                                            hb = _v48_build_heartbeat_response(
                                                hb_seq
                                            )
                                            _v48_send_app(
                                                conn, active_tgame_key, hb,
                                                label,
                                                "ZN2C_RES_HEARTBEAT v72-roomalloc-accept-probe"
                                            )

                                        elif app["cmd"] == TGAME_ZN_REQ_CREATEACCOUNT:
                                            rsp_seq = (app["seq"] + 1) & 0xffffffff
                                            uin_now = _v150_role_uin(role_state)
                                            nick = None
                                            try:
                                                nick = _v5_parse_first_nickname(
                                                    app["body"]
                                                )
                                                ok, normalized_nick, reason = (
                                                    _v5_validate_first_nickname(nick)
                                                )
                                            except Exception as nick_e:
                                                ok = False
                                                normalized_nick = ""
                                                reason = f"parse:{nick_e}"

                                            try:
                                                current_nickname = (
                                                    PLAYER_DB.load_nickname(uin_now)
                                                )
                                            except Exception as nick_db_e:
                                                current_nickname = None
                                                ok = False
                                                reason = (
                                                    "db-load:"
                                                    f"{type(nick_db_e).__name__}:"
                                                    f"{nick_db_e}"
                                                )

                                            # FIRST-NICKNAME-v26:
                                            # The stock CreateRole flow is valid while this
                                            # login is explicitly awaiting A002, or when A002
                                            # is a retransmit of the nickname already persisted
                                            # for this same UIN.
                                            forced_first_account = bool(
                                                role_state.get(
                                                    "v20_force_a001_0401"
                                                )
                                            )
                                            remembered_awaiting = bool(
                                                role_state.get(
                                                    "v5_awaiting_first_nickname"
                                                )
                                            )
                                            db_awaiting = current_nickname is None
                                            same_nickname_retry = bool(
                                                ok
                                                and current_nickname
                                                and str(current_nickname).casefold()
                                                == normalized_nick.casefold()
                                            )
                                            eligible = bool(ok and (db_awaiting or same_nickname_retry))
                                            awaiting = db_awaiting

                                            log(
                                                "ACCOUNT",
                                                "FIRST-NICKNAME-v26 A002 CreateAccount "
                                                f"uin={uin_now} nick={nick!r} "
                                                f"awaiting={awaiting} "
                                                f"forced0401={forced_first_account} "
                                                f"remembered={remembered_awaiting} "
                                                f"db_awaiting={db_awaiting} "
                                                f"db_nickname={current_nickname!r} "
                                                f"same_retry={same_nickname_retry} "
                                                f"valid={ok} eligible={eligible} "
                                                f"reason={reason}",
                                            )

                                            if not eligible:
                                                reject_result = (
                                                    ZONE_FAIL_ILLEGAL_NICKNAME
                                                    if not ok
                                                    else ZONE_FAIL_NOACCOUNTEXIST
                                                )
                                                fail_rsp = _v48_build_createaccount_response(
                                                    rsp_seq,
                                                    reject_result,
                                                )
                                                _v48_send_app(
                                                    conn,
                                                    active_tgame_key,
                                                    fail_rsp,
                                                    label,
                                                    "ZN2C_RES_CREATEACCOUNT first-nickname-v26f "
                                                    f"result=0x{reject_result:04x} rejected",
                                                )
                                            elif same_nickname_retry:
                                                # A002 can be retransmitted after the DB commit.
                                                # Never rebuild/replay the complete first-account
                                                # profile a second time. If this live CreateRole
                                                # transaction is still awaiting completion, keep
                                                # (or recover) only the pending A146/deferred-A006
                                                # state needed to finish it.
                                                if (
                                                    forced_first_account
                                                    or remembered_awaiting
                                                    or role_state.get(
                                                        "first_account_change_role_pending"
                                                    )
                                                ):
                                                    role_state[
                                                        "first_account_change_role_pending"
                                                    ] = True
                                                    role_state.setdefault(
                                                        "first_nickname_v26_deferred_login_groups",
                                                        _v140_login_prop_groups(),
                                                    )

                                                success_rsp = _v48_build_createaccount_response(
                                                    rsp_seq,
                                                    ZONE_ERR_SUCC,
                                                )
                                                _v48_send_app(
                                                    conn,
                                                    active_tgame_key,
                                                    success_rsp,
                                                    label,
                                                    "ZN2C_RES_CREATEACCOUNT first-nickname-v26 "
                                                    "cmd=0xA003 result=0x8100 "
                                                    "idempotent-same-nickname",
                                                )
                                                log(
                                                    "ACCOUNT",
                                                    "FIRST-NICKNAME-v26 A002 idempotent retry "
                                                    f"uin={uin_now} "
                                                    f"nickname={current_nickname!r}; "
                                                    "no duplicate profile replay",
                                                )
                                            else:
                                                try:
                                                    # Atomic claim closes the A144->A002 race:
                                                    # availability is re-checked under SQLite's
                                                    # write lock before the nickname is committed.
                                                    PLAYER_DB.claim_nickname(
                                                        uin_now,
                                                        normalized_nick,
                                                        require_unclaimed=True,
                                                    )
                                                except Exception as db_e:
                                                    claim_result = (
                                                        _v26_nickname_claim_failure_result(db_e)
                                                    )
                                                    log(
                                                        "ACCOUNT",
                                                        "FIRST-NICKNAME-v26f DB claim failed: "
                                                        f"{type(db_e).__name__}: {db_e}; "
                                                        f"client_result=0x{claim_result:04x}",
                                                    )
                                                    fail_rsp = _v48_build_createaccount_response(
                                                        rsp_seq,
                                                        claim_result,
                                                    )
                                                    _v48_send_app(
                                                        conn,
                                                        active_tgame_key,
                                                        fail_rsp,
                                                        label,
                                                        "ZN2C_RES_CREATEACCOUNT first-nickname-v26f "
                                                        f"result=0x{claim_result:04x} "
                                                        "nickname-claim-failure",
                                                    )
                                                else:
                                                    role_state.pop(
                                                        "v12_force_blank_nickname", None
                                                    )
                                                    role_state.pop(
                                                        "v13_no_role_login", None
                                                    )
                                                    role_state["nickname"] = normalized_nick
                                                    role_state[
                                                        "v5_awaiting_first_nickname"
                                                    ] = False
                                                    role_state.pop(
                                                        "v20_force_a001_0401", None
                                                    )
                                                    role_state[
                                                        "first_account_change_role_pending"
                                                    ] = True
                                                    with _V150_ZONE_LOCK:
                                                        session = _V150_ZONE_SESSIONS.get(
                                                            uin_now
                                                        )
                                                        if session is not None:
                                                            session["nickname"] = normalized_nick

                                                    success_rsp = _v48_build_createaccount_response(
                                                        rsp_seq,
                                                        ZONE_ERR_SUCC,
                                                    )
                                                    _v48_send_app(
                                                        conn,
                                                        active_tgame_key,
                                                        success_rsp,
                                                        label,
                                                        "ZN2C_RES_CREATEACCOUNT first-nickname-v21 "
                                                        "cmd=0xA003 result=0x8100 "
                                                        f"nickname={normalized_nick!r}",
                                                    )

                                                    # Publish the profile only after the stock
                                                    # CreateAccount request succeeds.
                                                    pinfo = _v48_build_playerinfo(
                                                        0,
                                                        uin=uin_now,
                                                        cur_role_gid=0,
                                                        nickname=normalized_nick,
                                                    )
                                                    _v48_send_app(
                                                        conn,
                                                        active_tgame_key,
                                                        pinfo,
                                                        label,
                                                        "ZN2C_NTF_PLAYERINFO first-nickname-v5 "
                                                        "post-A003 CurRoleGID=0",
                                                    )

                                                    # FIRST-NICKNAME-v26:
                                                    #
                                                    # Proven live client ordering bug:
                                                    #   OnCreateRoleReturn
                                                    #   -> OnNotifyPropsInfo (FName 0x12A16)
                                                    #      enters with CreateRole+0x228 bit0 == 0
                                                    #      and therefore skips its 0x12C26 gate callee
                                                    #   -> OnResChangeLoginRole (FName 0x12AD6)
                                                    #      then sets CreateRole+0x228 bit0 == 1
                                                    #
                                                    # The previous first-account path sent A006
                                                    # PlayerProps while still inside the A002/A003
                                                    # handler, before the server could read the
                                                    # already-queued A146 request.  That fires
                                                    # OnNotifyPropsInfo too early and it is never
                                                    # retriggered after A147.
                                                    #
                                                    # Defer ONLY the first-account A006 groups.
                                                    # A146/A147 establishes the bit0 completion
                                                    # latch first; the A146 handler publishes these
                                                    # groups immediately afterward.
                                                    login_groups = _v140_login_prop_groups()
                                                    role_state[
                                                        "first_nickname_v26_deferred_login_groups"
                                                    ] = login_groups
                                                    log(
                                                        "ACCOUNT",
                                                        "FIRST-NICKNAME-v26 deferred A006 PlayerProps "
                                                        f"until after A147 groups={len(login_groups)}",
                                                    )

                                                    pinfo_after = _v48_build_playerinfo(
                                                        0,
                                                        uin=uin_now,
                                                        cur_role_gid=_r13_wire_current_role_gid(
                                                            uin_now
                                                        ),
                                                        nickname=normalized_nick,
                                                    )
                                                    _v48_send_app(
                                                        conn,
                                                        active_tgame_key,
                                                        pinfo_after,
                                                        label,
                                                        "ZN2C_NTF_PLAYERINFO first-nickname-v5 "
                                                        "post-A003 role-selected-profile; props-deferred",
                                                    )
                                                    _v140_send_wallet_sync(
                                                        conn,
                                                        active_tgame_key,
                                                        label,
                                                        reason=UPDATE_REASON_TP_BALANCE,
                                                        prefix="first-account",
                                                    )
                                                    hints = _v48_build_zonehints(0)
                                                    _v48_send_app(
                                                        conn,
                                                        active_tgame_key,
                                                        hints,
                                                        label,
                                                        "ZN2C_NTF_ZONE_HINTS first-nickname-v5",
                                                    )
                                                    pending_zone_profile = None
                                                    log(
                                                        "ACCOUNT",
                                                        "FIRST-NICKNAME-v21 COMPLETE "
                                                        f"uin={uin_now} "
                                                        f"nickname={normalized_nick!r}; "
                                                        "SQLite persisted; profile published with A006 deferred",
                                                    )

                                        elif app["cmd"] == TGAME_ZN_REQ_CHANGE_ROLE:
                                            # FIRST-NICKNAME-v26:
                                            # This A146/A147 compatibility path is scoped only
                                            # to a just-completed first-account A002. Existing
                                            # accounts must not have arbitrary role changes
                                            # acknowledged by this special handler.
                                            # Stock client emits A146 immediately after a
                                            # successful first-account A003.  v21 persisted
                                            # the nickname correctly but left this request
                                            # unhandled, so the CreateRole UI completion
                                            # callback never received A147.
                                            uin_now = _v150_role_uin(role_state)
                                            try:
                                                rebel_role_index, gsdu_role_index = (
                                                    _v22_parse_change_login_role(
                                                        app["body"]
                                                    )
                                                )
                                            except Exception as role_e:
                                                log(
                                                    "ACCOUNT",
                                                    "FIRST-NICKNAME-v22 A146 parse failed: "
                                                    f"{type(role_e).__name__}: {role_e}",
                                                )
                                            else:
                                                first_account_pending = bool(
                                                    role_state.get(
                                                        "first_account_change_role_pending"
                                                    )
                                                )
                                                if not first_account_pending:
                                                    log(
                                                        "ACCOUNT",
                                                        "FIRST-NICKNAME-v26b A146 ignored outside "
                                                        "first-account completion scope: "
                                                        f"uin={uin_now} "
                                                        f"rebel_role_index={rebel_role_index} "
                                                        f"gsdu_role_index={gsdu_role_index}",
                                                    )
                                                    continue

                                                log(
                                                    "ACCOUNT",
                                                    "FIRST-NICKNAME-v26b A146 accepted inside "
                                                    "first-account completion scope: "
                                                    f"uin={uin_now} "
                                                    f"rebel_role_index={rebel_role_index} "
                                                    f"gsdu_role_index={gsdu_role_index}",
                                                )

                                                nickname_now = (
                                                    role_state.get("nickname")
                                                    or PLAYER_DB.load_nickname(uin_now)
                                                    or ""
                                                )
                                                cur_role_gid = _r13_wire_current_role_gid(
                                                    uin_now
                                                )
                                                log(
                                                    "ACCOUNT",
                                                    "FIRST-NICKNAME-v22 A146 ChangeLoginRole "
                                                    f"uin={uin_now} "
                                                    f"rebel_role_index={rebel_role_index} "
                                                    f"gsdu_role_index={gsdu_role_index} "
                                                    f"nickname={nickname_now!r} "
                                                    f"cur_role_gid=0x{cur_role_gid:016x}",
                                                )

                                                rsp = _v22_build_change_login_role_response()
                                                _v48_send_app(
                                                    conn,
                                                    active_tgame_key,
                                                    rsp,
                                                    label,
                                                    "ZN2C_RES_CHANGE_ROLE first-nickname-v22 "
                                                    "cmd=0xA147 result=0x8100",
                                                )

                                                # FIRST-NICKNAME-v26:
                                                # Preserve the proven A147 -> A005 completion
                                                # sequence, then publish the A006 groups that were
                                                # intentionally deferred from the A003 handler.
                                                #
                                                # TCP ordering guarantees the client processes
                                                # A147 before these later notifications.  The live
                                                # v6 trace proved OnResChangeLoginRole sets
                                                # CreateRole+0x228 bit0, so the subsequent
                                                # OnNotifyPropsInfo event can now pass its bit0
                                                # gate and enter 0x12C26.
                                                role_info = _v48_build_playerinfo(
                                                    0,
                                                    uin=uin_now,
                                                    cur_role_gid=cur_role_gid,
                                                    nickname=nickname_now,
                                                )
                                                _v48_send_app(
                                                    conn,
                                                    active_tgame_key,
                                                    role_info,
                                                    label,
                                                    "ZN2C_NTF_PLAYERINFO first-nickname-v26 "
                                                    "post-A147 "
                                                    f"CurRoleGID=0x{cur_role_gid:016x}",
                                                )

                                                deferred_groups = role_state.get(
                                                    "first_nickname_v26_deferred_login_groups"
                                                )
                                                if not deferred_groups:
                                                    # Recovery for a same-session retransmit or
                                                    # partial state loss: rebuild the authoritative
                                                    # groups but still keep them deferred until
                                                    # after A147.
                                                    deferred_groups = _v140_login_prop_groups()

                                                if deferred_groups:
                                                    for group_index, group in enumerate(
                                                        deferred_groups
                                                    ):
                                                        is_last = (
                                                            group_index
                                                            == len(deferred_groups) - 1
                                                        )
                                                        props_pkt = _v127_build_playerprops_chunk(
                                                            group,
                                                            is_last,
                                                            session_uin=uin_now,
                                                        )
                                                        _v48_send_app(
                                                            conn,
                                                            active_tgame_key,
                                                            props_pkt,
                                                            label,
                                                            "ZN2C_NTF_PLAYERPROPS first-nickname-v26 "
                                                            "deferred-post-A147 "
                                                            f"chunk={group_index+1}/"
                                                            f"{len(deferred_groups)} "
                                                            f"is_last={int(is_last)} "
                                                            f"prop_count={len(group)}",
                                                        )
                                                    log(
                                                        "ACCOUNT",
                                                        "FIRST-NICKNAME-v26 released deferred A006 "
                                                        f"after A147 groups={len(deferred_groups)}",
                                                    )
                                                    role_state.pop(
                                                        "first_nickname_v26_deferred_login_groups",
                                                        None,
                                                    )
                                                    role_state.pop(
                                                        "first_account_change_role_pending",
                                                        None,
                                                    )
                                                else:
                                                    log(
                                                        "ACCOUNT",
                                                        "FIRST-NICKNAME-v26 no deferred A006 groups "
                                                        "present on A146; preserved A147/A005 behavior",
                                                    )

                                                log(
                                                    "ACCOUNT",
                                                    "FIRST-NICKNAME-v26 ROLE COMPLETE "
                                                    f"uin={uin_now}; A147 + A005 + deferred-A006 sent",
                                                )

                                        elif app["cmd"] == TGAME_ZN_REQ_PLMATCH_SEASON_TIME:
                                            padding = _v23_parse_season_time_request(
                                                app["body"], "PLMatchSeasonTime"
                                            )
                                            log(
                                                "ACCOUNT",
                                                "FIRST-NICKNAME-v26 F124 PLMatchSeasonTime "
                                                f"padding=0x{padding:02x}",
                                            )
                                            rsp = _v26_build_season_time_response(
                                                TGAME_ZN_RES_PLMATCH_SEASON_TIME
                                            )
                                            _v48_send_app(
                                                conn,
                                                active_tgame_key,
                                                rsp,
                                                label,
                                                "ZN2C_RES_PLMATCHSEASONTIME first-nickname-v26b "
                                                "cmd=0xF125 verified-v25 result-prefix compatibility",
                                            )

                                        elif app["cmd"] == TGAME_ZN_REQ_CLMATCH_SEASON_TIME:
                                            padding = _v23_parse_season_time_request(
                                                app["body"], "CLMatchSeasonTime"
                                            )
                                            log(
                                                "ACCOUNT",
                                                "FIRST-NICKNAME-v26 F126 CLMatchSeasonTime "
                                                f"padding=0x{padding:02x}",
                                            )
                                            rsp = _v26_build_season_time_response(
                                                TGAME_ZN_RES_CLMATCH_SEASON_TIME
                                            )
                                            _v48_send_app(
                                                conn,
                                                active_tgame_key,
                                                rsp,
                                                label,
                                                "ZN2C_RES_CLMATCHSEASONTIME first-nickname-v26b "
                                                "cmd=0xF127 verified-v25 result-prefix compatibility",
                                            )

                                        elif app["cmd"] == TGAME_ZN_REQ_MATCHROOMLIST:
                                            req = _v77_parse_match_room_list_request(
                                                app["body"]
                                            )
                                            uin_now = _v150_role_uin(role_state)
                                            current_room = V150_ROOM_REGISTRY.room_for_player(uin_now)
                                            if (
                                                current_room is not None
                                                and not role_state.get("v138_leave_pending")
                                            ):
                                                log(
                                                    "ROOM",
                                                    f"r11 suppress stale A100 uin={uin_now} "
                                                    f"already_in_room={current_room['room_id']}",
                                                )
                                            else:
                                                rooms = V150_ROOM_REGISTRY.list_rooms(include_started=True)
                                                total, page = _v150_filter_match_rooms(req, rooms)
                                                rsp = _v150_build_match_room_list_response(total, page)
                                                _v48_send_app(
                                                    conn,
                                                    active_tgame_key,
                                                    rsp,
                                                    label,
                                                    "ZN2C_RES_MATCHROOMLIST r11-shared "
                                                    f"cmd=0xA102 result=0x8100 total={total} "
                                                    f"count={len(page)} rooms="
                                                    + ",".join(
                                                        f"{r['room_id']}:{r['name']}:{r['fighter_count']}/{r['fighter_capacity']}"
                                                        for r in page
                                                    ),
                                                )

                                                if role_state.get("v138_leave_pending"):
                                                    # A107 already removed only THIS player; this A100
                                                    # is UI finalization only and must never full-release
                                                    # a shared room that still has other members.
                                                    role_state["v83_in_match_room"] = False
                                                    role_state.pop("v79_created_match_room", None)
                                                    role_state.pop("v143b_ds_room_id", None)
                                                    role_state.pop("v143b_ds_endpoint", None)
                                                    role_state.pop("v132_pve_afdev_handoff_sent", None)
                                                    role_state.pop("v88_match_seat", None)
                                                    role_state.pop("v88_match_camp", None)
                                                    role_state.pop("v132_match_ready", None)
                                                    role_state.pop("v134_ready_ntf_sent", None)
                                                    role_state.pop("v138_leave_pending", None)
                                                    log(
                                                        "ROOM",
                                                        f"r11 leave finalized uin={uin_now}; "
                                                        "returned to shared A100 room browser",
                                                    )

                                        elif app["cmd"] == TGAME_ZN_REQ_CREATEMATCHROOM:
                                            cr = _v79_parse_create_match_room_request(
                                                app["body"]
                                            )

                                            owner_uin = _v150_role_uin(role_state)
                                            owner_name = _v150_role_nickname(role_state)
                                            existing_room = V150_ROOM_REGISTRY.room_for_player(
                                                owner_uin
                                            )
                                            if existing_room is not None:
                                                log(
                                                    "ROOM",
                                                    f"A10A create rejected owner={owner_uin}: "
                                                    f"player-already-in-room:{existing_room['room_id']}",
                                                )
                                                continue

                                            ds_allocation = None
                                            if V143B_DS_CONFIG.enabled:
                                                try:
                                                    ds_allocation = _v143b_reserve_room_ds(
                                                        role_state, cr
                                                    )
                                                except DSCapacityError as exc:
                                                    fail_rsp = _v78_build_create_match_room_response(
                                                        V143B_ZONE_ERR_NO_DS_CAPACITY
                                                    )
                                                    _v48_send_app(
                                                        conn, active_tgame_key, fail_rsp, label,
                                                        "ZN2C_RES_CREATEMATCHROOM stable-v143b "
                                                        "NO-DS-CAPACITY "
                                                        f"cmd=0xA10B result=0x{V143B_ZONE_ERR_NO_DS_CAPACITY:04x}",
                                                    )
                                                    log(
                                                        "DS-SPAWNER",
                                                        f"A10A rejected owner={role_state.get('uin')} "
                                                        f"because DS pool is unavailable: {exc}",
                                                    )
                                                    continue

                                            created_room = {
                                                "room_id": (
                                                    int(ds_allocation.room_id)
                                                    if ds_allocation is not None else 1
                                                ),
                                                "display_id": (
                                                    (int(ds_allocation.room_id) & 0xFFFF) or 1
                                                    if ds_allocation is not None else 1
                                                ),
                                                "qqtalk_room_id": 0,
                                                "sub_channel_id": 1,
                                                "name": cr["name"],
                                                "owner_name": "LocalPlayer",
                                                "match_settings_wire": cr["match_settings_wire"],
                                                "mode_id": cr["mode_id"],
                                                "map_id": cr["map_id"],
                                                "sub_mode_id": cr["sub_mode_id"],
                                                "flags": cr["flags"],
                                                "no_late_join": _v150_no_late_join_from_flags(cr["flags"]),
                                                "fighter_capacity": cr["fighter_capacity"],
                                                "observer_capacity": cr["observer_capacity"],
                                                "fighter_count": 1,
                                                "observer_count": 0,
                                                "password": cr["password"],
                                                "map_string": cr.get("map_string", ""),
                                                "ds_slot": (
                                                    int(ds_allocation.slot)
                                                    if ds_allocation is not None else None
                                                ),
                                                "ds_public_port": (
                                                    int(ds_allocation.public_port)
                                                    if ds_allocation is not None else TGAME_AFDEV_PORT
                                                ),
                                            }
                                            try:
                                                created_room = V150_ROOM_REGISTRY.create_room(
                                                    created_room,
                                                    owner_uin=owner_uin,
                                                    owner_name=owner_name,
                                                )
                                                role_state["v79_created_match_room"] = created_room
                                                role_state["v143b_ds_room_id"] = int(created_room["room_id"])
                                                role_state.pop("v138_leave_pending", None)
                                                _v150_sync_role_states(created_room)
                                            except Exception as create_e:
                                                if ds_allocation is not None:
                                                    try:
                                                        V143B_DS_SPAWNER.release_lobby(
                                                            int(ds_allocation.room_id),
                                                            reason=(
                                                                "A10A registry/create rollback: "
                                                                f"{type(create_e).__name__}: {create_e}"
                                                            ),
                                                        )
                                                    except Exception as release_e:
                                                        log(
                                                            "DS-SPAWNER",
                                                            f"A10A rollback release failed room="
                                                            f"{int(ds_allocation.room_id)}: {release_e}",
                                                        )
                                                role_state.pop("v143b_ds_room_id", None)
                                                role_state.pop("v79_created_match_room", None)
                                                # If create_room inserted the owner before a later
                                                # compatibility sync failed, remove that registry
                                                # mutation as part of the same transaction.
                                                try:
                                                    rollback_room = V150_ROOM_REGISTRY.room_for_player(
                                                        owner_uin
                                                    )
                                                    expected_room_id = int(created_room["room_id"])
                                                    if (
                                                        rollback_room is not None
                                                        and int(rollback_room["room_id"]) == expected_room_id
                                                    ):
                                                        rollback_leave = V150_ROOM_REGISTRY.leave_room(
                                                            owner_uin
                                                        )
                                                        if rollback_leave:
                                                            log(
                                                                "ROOM",
                                                                f"A10A registry rollback removed owner={owner_uin} "
                                                                f"room={rollback_leave['room_id']}",
                                                            )
                                                except Exception as rollback_e:
                                                    log(
                                                        "ROOM",
                                                        f"A10A registry rollback failed owner={owner_uin}: "
                                                        f"{rollback_e}",
                                                    )
                                                log(
                                                    "ROOM",
                                                    f"A10A create rejected owner={owner_uin}: "
                                                    f"{type(create_e).__name__}: {create_e}",
                                                )
                                                continue

                                            log(
                                                label,
                                                "C2ZN_REQ_CREATEMATCHROOM v86: "
                                                f"body_len={len(app['body'])} "
                                                f"room_name={cr['name']!r} "
                                                f"mode=0x{cr['mode_id']:08x} "
                                                f"map=0x{cr['map_id']:04x} "
                                                f"map_string={cr.get('map_string', '')!r} "
                                                f"submode=0x{cr['sub_mode_id']:08x} "
                                                f"flags=0x{cr['flags']:08x} "
                                                f"fighters={cr['fighter_capacity']} "
                                                f"observers={cr['observer_capacity']} "
                                                f"password={cr['password']!r}"
                                            )

                                            # A10B uses the zone success value 0x8100.
                                            # v80's AA00 experiment is rejected by TGame as
                                            # "Failed to create room", so keep the proven 8100.
                                            rsp = _v78_build_create_match_room_response()
                                            _v48_send_app(
                                                conn, active_tgame_key, rsp,
                                                label,
                                                "ZN2C_RES_CREATEMATCHROOM v86 "
                                                "cmd=0xA10B result=0x8100"
                                            )

                                            # v81's A106-only probe was ignored by the
                                            # creator and TGame resumed A100 polling.  Send the
                                            # creator-side A105 response with the full
                                            # MatchRoomInfo instead.  Do NOT also send A106 in
                                            # this controlled probe; A106 is kept for later
                                            # other-player notifications.
                                            enter_rsp = _v150_build_res_enter_match_room(
                                                created_room
                                            )
                                            _v48_send_app(
                                                conn, active_tgame_key, enter_rsp,
                                                label,
                                                "ZN2C_RES_ENTERMATCHROOM v86 "
                                                f"cmd=0xA105 result=0x8100 room_id={created_room['room_id']} "
                                                "sub=1 players=1 owner=LocalPlayer "
                                                "state=Unready(8) seat=0"
                                            )

                                            # Flip this before the next queued lobby poll is
                                            # dispatched so A100 cannot drag the client back
                                            # into channel state after A105.
                                            role_state["v83_in_match_room"] = True

                                            # Creator enters in A105 seat 0.
                                            role_state["v88_match_seat"] = 0

                                            # v93: the live Survival room sends A10D Camp=0
                                            # for all of the visible PVE slot clicks.  Treat
                                            # that as the room's current/single camp instead
                                            # of inheriting the earlier PvP left/right guess.
                                            # v94: initial A105 puts LocalPlayer in
                                            # seat 0, which the live room UI renders as the
                                            # top-left slot.  The client's click on the
                                            # opposite/right camp sends A10D Camp=0, so the
                                            # initial left camp is Camp=1 (Regular).
                                            role_state["v88_match_camp"] = 1

                                            # v85 critical wire fix:
                                            # MatchRoomInfo.PlayerCount is uint8 in
                                            # proto_c2zn.tdr. v82-v84 wrote uint16, shifting
                                            # PlayerInfos by one byte and making the nested
                                            # room/player state malformed. Do NOT send A106 in
                                            # this isolation test; A105 already carries the
                                            # creator in PlayerInfos[0].
                                            log(
                                                label,
                                                "v85: A10B + corrected A105 sent "
                                                "(PlayerCount=u8, PlayerInfos aligned); "
                                                "A106 intentionally omitted; room-state hold "
                                                "enabled and stale A100/A102 suppressed"
                                            )

                                        elif app["cmd"] in (TGAME_ZN_REQ_ENTERMATCHROOM, 0xA120):
                                            er = (_v178_parse_trace_enter(app["body"], role_state) if app["cmd"] == 0xA120 else _v150_parse_enter_match_room(app["body"]))
                                            uin_now = _v150_role_uin(role_state)
                                            nickname_now = _v150_role_nickname(role_state)
                                            prior_room = V150_ROOM_REGISTRY.room_for_player(uin_now)
                                            joined_new_member = prior_room is None
                                            try:
                                                joined_room, member, existing_uins = V150_ROOM_REGISTRY.join_room(
                                                    uin=uin_now,
                                                    nickname=nickname_now,
                                                    room_id=er["room_id"],
                                                    password=er["password"],
                                                    observer=er["observer"],
                                                )
                                                if (V143B_DS_CONFIG.enabled and not (app["cmd"] == 0xA120 and er.get("invite_id") is not None)):
                                                    V143B_DS_SPAWNER.register_room_player(
                                                        int(joined_room["room_id"]),
                                                        uin_now,
                                                    )
                                            except (RoomRegistryError, SpawnerError) as room_e:
                                                if joined_new_member:
                                                    try:
                                                        rolled_back = V150_ROOM_REGISTRY.rollback_join(
                                                            uin_now, er["room_id"]
                                                        )
                                                        if rolled_back:
                                                            log(
                                                                "ROOM",
                                                                f"r11 A104 rolled back registry join "
                                                                f"uin={uin_now} room={er['room_id']} after downstream failure",
                                                            )
                                                    except RoomRegistryError as rollback_e:
                                                        log(
                                                            "ROOM",
                                                            f"r11 A104 rollback failed uin={uin_now} "
                                                            f"room={er['room_id']}: {rollback_e}",
                                                        )
                                                log(
                                                    "ROOM",
                                                    f"r11 A104 join rejected uin={uin_now} "
                                                    f"room={er['room_id']} reason={type(room_e).__name__}:{room_e}; "
                                                    + (
                                                        "VERIFIED No Late Join enforced; "
                                                        if "room-no-late-join" in str(room_e)
                                                        else ""
                                                    )
                                                    + "no guessed failure Result emitted",
                                                )
                                            else:
                                                role_state["v79_created_match_room"] = joined_room
                                                role_state["v143b_ds_room_id"] = int(joined_room["room_id"])
                                                role_state["v83_in_match_room"] = True
                                                role_state["v88_match_seat"] = int(member["seat_index"])
                                                role_state["v88_match_camp"] = int(member.get("camp", 1))
                                                role_state.pop("v138_leave_pending", None)
                                                _v150_sync_role_states(joined_room)

                                                enter_rsp = _v150_build_res_enter_match_room(joined_room)
                                                if app["cmd"] == 0xA120:
                                                    # Same MatchRoomInfo layout, distinct native callback for trace entry.
                                                    enter_rsp = _v62_build_server_app(TGAME_ZN_MAGIC, 0xA121, _v48_u16(0x8300) + enter_rsp[10:])
                                                    invite_id = er.get('invite_id')
                                                    if invite_id is not None:
                                                        with _V150_ZONE_LOCK:
                                                            _V177_ROOM_INVITES.pop(invite_id, None)
                                                        decision = _v62_build_server_app(TGAME_ZN_MAGIC, 0xA316,
                                                            _v50_geo_tdr_string(nickname_now, 32) + _v48_u16(0x8300) + _v48_i32(0))
                                                        _v150_send_online(er['inviter'], decision, 'v178 invitation accepted and room joined')
                                                log('SOCIAL', f'v178 room entry request=0x{app["cmd"]:04X} response=0x{(0xA121 if app["cmd"] == 0xA120 else TGAME_ZN_RES_ENTERMATCHROOM):04X} uin={uin_now} room={joined_room["room_id"]}')

                                                _v48_send_app(
                                                    conn,
                                                    active_tgame_key,
                                                    enter_rsp,
                                                    label,
                                                    "ZN2C_RES_ENTERMATCHROOM r11-shared "
                                                    f"cmd=0xA105 result=0x8100 room={joined_room['room_id']} "
                                                    f"players={len(joined_room['members'])} seat={member['seat_index']}",
                                                )

                                                if app["cmd"] == 0xA120:
                                                    # A121 reports trace success; A105 drives the stock room UI transition.
                                                    standard_enter_rsp = _v150_build_res_enter_match_room(joined_room)
                                                    _v48_send_app(
                                                        conn,
                                                        active_tgame_key,
                                                        standard_enter_rsp,
                                                        label,
                                                        f"ZN2C_RES_ENTERMATCHROOM invite-transition cmd=0xA105 room={joined_room['room_id']}",
                                                    )
                                                    log("SOCIAL", f"v182 sent normal A105 transition to accepted invitee uin={uin_now} room={joined_room['room_id']}")

                                                ntf = _v150_build_ntf_enter_match_room(member)
                                                notified = []
                                                for peer_uin in existing_uins:
                                                    if _v150_send_online(
                                                        peer_uin,
                                                        ntf,
                                                        "ZN2C_NTF_ENTERMATCHROOM r11-shared "
                                                        f"cmd=0xA106 join={nickname_now}({uin_now}) "
                                                        f"seat={member['seat_index']}",
                                                    ):
                                                        notified.append(int(peer_uin))

                                                log(
                                                    "ROOM",
                                                    f"r11 joined uin={uin_now} room={joined_room['room_id']} "
                                                    f"seat={member['seat_index']} existing={existing_uins} "
                                                    f"notified={notified}",
                                                )

                                                # LATEJOIN-v2: A105 put the player in the logical room.
                                                # If the round is already active, publish the existing
                                                # A11A DSInfo only to this new client. This is a state
                                                # sync, not the actual JoinMatch commit, so do not set
                                                # the per-player handoff guard yet.
                                                if joined_room.get("started"):
                                                    _latejoin_v2_send_running_match_a11a(
                                                        conn,
                                                        active_tgame_key,
                                                        label,
                                                        role_state,
                                                        int(joined_room["room_id"]),
                                                        reason="A103 entered already-started room",
                                                        commit_handoff=False,
                                                    )

                                        elif app["cmd"] == TGAME_ZN_REQ_LEAVEMATCHROOM:
                                            # Live capture:
                                            #   A107 body=0000 for the solo creator in seat 0.
                                            # Treat it as u16 SeatIndex for diagnostics, but
                                            # do not require it to match our cached seat; a
                                            # stale/malformed local cache must not trap the
                                            # client inside the room UI.
                                            leave_seat = (
                                                int.from_bytes(app["body"][:2], "big")
                                                if len(app["body"]) >= 2
                                                else int(role_state.get("v88_match_seat", 0))
                                            )

                                            room = role_state.get("v79_created_match_room")
                                            was_in_room = bool(
                                                role_state.get("v83_in_match_room")
                                            )
                                            cached_seat = int(
                                                role_state.get("v88_match_seat", 0)
                                            )

                                            log(
                                                label,
                                                "C2ZN_REQ_LEAVEMATCHROOM v135: "
                                                f"body_len={len(app['body'])} "
                                                f"body={app['body'].hex()} "
                                                f"seat={leave_seat} "
                                                f"cached_seat={cached_seat} "
                                                f"was_in_room={was_in_room} "
                                                f"room_id={room.get('room_id') if isinstance(room, dict) else None}"
                                            )

                                            # A107's live 2-byte body is LeaveReason, not the
                                            # seat index.  For the normal Exit-the-room button it
                                            # is 0x0000 (LEAVEROOM_NORMAL).  The creator seat is
                                            # separately tracked by the room state.
                                            leave_reason = leave_seat
                                            notify_seat = cached_seat

                                            # r11: remove this UIN from the shared stock-room registry
                                            # first, then mirror the same player-scoped change into the DS
                                            # spawner.  Other room/match members are preserved.
                                            uin_now = _v150_role_uin(role_state)
                                            shared_leave = V150_ROOM_REGISTRY.leave_room(uin_now)
                                            leave_ds = _v143b_remove_room_player(
                                                role_state,
                                                room,
                                                reason=f"A107 LeaveRoom reason=0x{leave_reason:04x}",
                                                authoritative_new_owner=(
                                                    shared_leave.get("new_owner_uin")
                                                    if shared_leave else None
                                                ),
                                            )
                                            if shared_leave and shared_leave.get("room"):
                                                _v150_sync_role_states(shared_leave["room"])
                                            role_state.pop("v143b_ds_endpoint", None)
                                            role_state.pop("v132_pve_afdev_handoff_sent", None)
                                            log(
                                                "DS-CLEANUP",
                                                "r10 A107 player-scoped cleanup "
                                                f"uin={int(role_state.get('uin') or 10001)} "
                                                f"result={leave_ds}",
                                            )

                                            # v138: use the actual stock callback payload shape.
                                            rsp = _v138_build_res_leave_match_room(
                                                leave_reason=leave_reason,
                                                error_desc="",
                                            )
                                            _v48_send_app(
                                                conn,
                                                active_tgame_key,
                                                rsp,
                                                label,
                                                "ZN2C_RES_LEAVEMATCHROOM v138 "
                                                "cmd=0xA108 result=0x8100 "
                                                f"leave_reason={leave_reason} error_desc='' "
                                                "schema=result:u16+reason:u16+tdr_string",
                                            )

                                            leave_ntf = _v138_build_ntf_leave_match_room(
                                                seat_index=notify_seat,
                                                leave_reason=leave_reason,
                                            )
                                            _v48_send_app(
                                                conn,
                                                active_tgame_key,
                                                leave_ntf,
                                                label,
                                                "ZN2C_NTF_LEAVEMATCHROOM v138 "
                                                f"cmd=0xA109 seat={notify_seat} "
                                                f"leave_reason={leave_reason} "
                                                "schema=seat:u16+reason:u16 self-notify",
                                            )

                                            # r11: remaining room members receive the same stock A109
                                            # so their room UI removes the leaving seat immediately.
                                            if shared_leave and shared_leave.get("room"):
                                                peer_sent = _v150_broadcast_room(
                                                    shared_leave["room_id"],
                                                    leave_ntf,
                                                    "ZN2C_NTF_LEAVEMATCHROOM r11-peer "
                                                    f"cmd=0xA109 seat={notify_seat} leave_reason={leave_reason}",
                                                    exclude=(uin_now,),
                                                )
                                                log(
                                                    "ROOM",
                                                    f"r11 A109 peer notify room={shared_leave['room_id']} "
                                                    f"leave_uin={uin_now} sent={peer_sent}",
                                                )

                                            # Do not destroy the backend room immediately.
                                            # v135/v137 did that before the stock client had
                                            # actually transitioned, causing backend/UI state
                                            # to diverge.  Mark the leave pending and allow the
                                            # expected follow-up A100 lobby refresh through.
                                            role_state["v138_leave_pending"] = True

                                            log(
                                                "ROOM",
                                                "v138 leave pending: full A108/A109 payloads sent; "
                                                "backend room retained until client requests A100",
                                            )

                                        elif app["cmd"] == TGAME_ZN_REQ_CHANGEMATCHROOMCAMP:
                                            # proto_c2zn.tdr:
                                            #   C2ZN_ReqChangeMatchRoomCamp = u8 Camp
                                            #   ZN2C_ResChangeMatchRoomCamp = u16 Result
                                            #   ZN2C_NtfChangeMatchRoomCamp =
                                            #       u16 OldSeatIndex | u16 NewSeatIndex
                                            requested_camp = (
                                                app["body"][0]
                                                if len(app["body"]) >= 1
                                                else 0
                                            )

                                            old_seat = int(
                                                role_state.get("v88_match_seat", 0)
                                            )
                                            current_camp = int(
                                                role_state.get("v88_match_camp", 1)
                                            )
                                            room = role_state.get(
                                                "v79_created_match_room"
                                            ) or {}
                                            mode_id = int(room.get("mode_id", 0))
                                            fighter_capacity = int(
                                                room.get("fighter_capacity", 0)
                                            )

                                            # ChangeCamp is a room/camp operation, not a
                                            # Survival-only operation. The PH room UI uses
                                            # the same With32 sparse seat halves for
                                            # compatible <=16-player rooms.
                                            #
                                            # FighterCapacity is the total player-count cap;
                                            # an N-player room exposes N/2 rows per side.
                                            # Odd/oversized layouts remain ACK-only until
                                            # their stock mapping is proven.
                                            uses_with32_sparse_camps = (
                                                2 <= fighter_capacity <= 16
                                                and fighter_capacity % 2 == 0
                                            )

                                            if (
                                                uses_with32_sparse_camps
                                                and requested_camp in (0, 1)
                                            ):
                                                # r20 generalized: mode-agnostic With32 path.
                                                try:
                                                    new_seat = _r20_map_pve_camp_seat(
                                                        old_seat,
                                                        requested_camp,
                                                        fighter_capacity,
                                                    )
                                                except ValueError as seat_e:
                                                    log(
                                                        "ROOM",
                                                        "r20 sparse seat map rejected request "
                                                        f"uin={_v150_role_uin(role_state)} "
                                                        f"old={old_seat} camp={requested_camp}: {seat_e}",
                                                    )
                                                    new_seat = old_seat

                                                row = old_seat % R20_CAMP_SPAN
                                                log(
                                                    label,
                                                    "C2ZN_REQ_CHANGEMATCHROOMCAMP r20-with32: "
                                                    f"camp=0x{requested_camp:02x} "
                                                    f"current_camp=0x{current_camp:02x} "
                                                    f"mode=0x{mode_id:08x} "
                                                    f"fighters={fighter_capacity} "
                                                    f"camp_span={R20_CAMP_SPAN} "
                                                    f"row={row} old_seat={old_seat} "
                                                    f"new_seat={new_seat} "
                                                    f"body={app['body'].hex()}"
                                                )

                                                rsp = _v88_build_res_change_match_room_camp()
                                                _v48_send_app(
                                                    conn, active_tgame_key, rsp, label,
                                                    "ZN2C_RES_CHANGEMATCHROOMCAMP r20 "
                                                    "cmd=0xA10E result=0x8100"
                                                )

                                                if new_seat != old_seat:
                                                    try:
                                                        moved_room, moved_member, registry_old_seat = (
                                                            V150_ROOM_REGISTRY.move_member(
                                                                _v150_role_uin(role_state),
                                                                new_seat,
                                                                requested_camp,
                                                            )
                                                        )
                                                    except RoomRegistryError as room_e:
                                                        log(
                                                            "ROOM",
                                                            f"r20 camp/seat move rejected "
                                                            f"uin={_v150_role_uin(role_state)} "
                                                            f"old={old_seat} new={new_seat}: {room_e}",
                                                        )
                                                    else:
                                                        _v150_sync_role_states(moved_room)
                                                        seat_refresh = _v150_build_ntf_enter_match_room(
                                                            moved_member
                                                        )
                                                        _v48_send_app(
                                                            conn, active_tgame_key,
                                                            seat_refresh, label,
                                                            "ZN2C_NTF_ENTERMATCHROOM r20-pre-A10F "
                                                            f"cmd=0xA106 uin={moved_member['uin']} "
                                                            f"seat={moved_member['seat_index']}",
                                                        )
                                                        ntf = _v88_build_ntf_change_match_room_camp(
                                                            registry_old_seat,
                                                            int(moved_member["seat_index"]),
                                                        )
                                                        sent_camp = _v150_broadcast_room(
                                                            moved_room["room_id"],
                                                            ntf,
                                                            "ZN2C_NTF_CHANGEMATCHROOMCAMP r20-shared "
                                                            f"cmd=0xA10F old_seat={registry_old_seat} "
                                                            f"new_seat={moved_member['seat_index']}",
                                                        )
                                                        if not sent_camp:
                                                            _v48_send_app(
                                                                conn, active_tgame_key,
                                                                ntf, label,
                                                                "ZN2C_NTF_CHANGEMATCHROOMCAMP r20-fallback "
                                                                f"cmd=0xA10F old_seat={registry_old_seat} "
                                                                f"new_seat={moved_member['seat_index']}",
                                                            )
                                                        role_state["v88_match_seat"] = int(
                                                            moved_member["seat_index"]
                                                        )
                                                        role_state["v88_match_camp"] = requested_camp
                                                else:
                                                    log(
                                                        label,
                                                        "r20: requested camp already owns "
                                                        f"seat={old_seat}; A10F suppressed"
                                                    )

                                            else:
                                                # Unsupported camp/layout semantics: ACK only.
                                                # Do not mutate odd-sized, >16-player, or
                                                # non-0/1 camp layouts without stock evidence.
                                                log(
                                                    label,
                                                    "C2ZN_REQ_CHANGEMATCHROOMCAMP v94: "
                                                    f"camp=0x{requested_camp:02x} "
                                                    f"mode=0x{mode_id:08x} "
                                                    f"fighters={fighter_capacity}; "
                                                    "unsupported With32 layout/camp -> ACK only"
                                                )
                                                rsp = _v88_build_res_change_match_room_camp()
                                                _v48_send_app(
                                                    conn,
                                                    active_tgame_key,
                                                    rsp,
                                                    label,
                                                    "ZN2C_RES_CHANGEMATCHROOMCAMP v94 "
                                                    "cmd=0xA10E result=0x8100 "
                                                    "unsupported-layout-or-camp-no-A10F"
                                                )

                                        elif app["cmd"] == TGAME_ZN_REQ_SETMATCHROOMREADY:
                                            # LATEJOIN-v2: the stock PH UI emits the same A110
                                            # empty request both for Ready and for the subsequent
                                            # Cancel click. Derive the transition from authoritative
                                            # per-player state instead of hardcoding ready=True.
                                            requester_uin = _v150_role_uin(role_state)
                                            room_before_ready = V150_ROOM_REGISTRY.room_for_player(
                                                requester_uin
                                            ) or {}
                                            member_before_ready = next(
                                                (
                                                    m for m in room_before_ready.get("members", [])
                                                    if int(m.get("uin", -1)) == int(requester_uin)
                                                ),
                                                None,
                                            )
                                            was_ready = bool(
                                                member_before_ready.get("ready", False)
                                                if isinstance(member_before_ready, dict)
                                                else role_state.get("v132_match_ready", False)
                                            )
                                            ready = not was_ready
                                            ready_state = (
                                                TGAME_PLAYERSTATE_READYTOMATCH
                                                if ready
                                                else TGAME_PLAYERSTATE_UNREADY
                                            )

                                            # Preserve the existing previous-round reconciliation,
                                            # but only when transitioning INTO Ready.
                                            if ready and role_state.get("v132_pve_afdev_handoff_sent"):
                                                room_for_ready = (
                                                    V150_ROOM_REGISTRY.room_for_player(requester_uin)
                                                    or role_state.get("v79_created_match_room")
                                                    or {}
                                                )
                                                room_id_ready = room_for_ready.get("room_id")
                                                reconcile_result = None
                                                if room_id_ready is not None:
                                                    try:
                                                        reconcile_result = _v143b_quit_match_player(
                                                            role_state,
                                                            room_for_ready,
                                                            reason=(
                                                                "A110 Ready room-UI reconciliation "
                                                                "(previous A11A still armed / missed A117)"
                                                            ),
                                                        )
                                                    except SpawnerError as reconcile_e:
                                                        log(
                                                            "DS-REJOIN",
                                                            f"A110 reconciliation warning room={room_id_ready} "
                                                            f"uin={requester_uin}: {reconcile_e}",
                                                        )

                                                _v143b_clear_player_handoff_state(role_state)

                                                if (
                                                    room_id_ready is not None
                                                    and isinstance(reconcile_result, dict)
                                                    and (
                                                        reconcile_result.get("ended_round")
                                                        or reconcile_result.get("state") == "ROUND_ENDED"
                                                    )
                                                ):
                                                    try:
                                                        _v143b_reset_room_after_round(
                                                            int(room_id_ready),
                                                            "A110 Ready after returning from prior PvE round",
                                                        )
                                                    except RoomRegistryError as reset_e:
                                                        log(
                                                            "DS-REJOIN",
                                                            f"A110 room reset warning room={room_id_ready}: {reset_e}",
                                                        )

                                                log(
                                                    "DS-REJOIN",
                                                    "A110 cleared stale previous-round handoff "
                                                    f"uin={requester_uin} room={room_id_ready} "
                                                    f"reconcile={reconcile_result}",
                                                )

                                            role_state["v132_match_ready"] = ready
                                            role_state["v147_room_player_state"] = ready_state
                                            ready_room_snapshot = V150_ROOM_REGISTRY.set_ready(
                                                requester_uin, ready
                                            )
                                            if ready_room_snapshot is not None:
                                                _v150_sync_role_states(ready_room_snapshot)

                                            # A112 is the shared state notification for BOTH
                                            # transitions: 9=ReadyToMatch, 8=Unready/Cancel.
                                            ready_seat = int(
                                                role_state.get("v88_match_seat", 0)
                                            )
                                            ntf = _v134_build_ntf_set_match_room_ready(
                                                ready_seat,
                                                ready_state,
                                            )
                                            room_now = role_state.get("v79_created_match_room") or {}
                                            room_id_now = room_now.get("room_id")
                                            sent_ready = (
                                                _v150_broadcast_room(
                                                    room_id_now,
                                                    ntf,
                                                    "ZN2C_NTF_SETREADY LATEJOIN-v2-shared "
                                                    f"cmd=0xA112 seat={ready_seat} "
                                                    f"state={ready_state} "
                                                    f"body={(_v48_u16(ready_seat) + _v48_u32(ready_state)).hex()}",
                                                    tpdu_cmd=2,
                                                )
                                                if room_id_now is not None
                                                else []
                                            )
                                            if not sent_ready:
                                                _v48_send_app(
                                                    conn,
                                                    active_tgame_key,
                                                    ntf,
                                                    label,
                                                    "ZN2C_NTF_SETREADY LATEJOIN-v2-fallback "
                                                    f"cmd=0xA112 seat={ready_seat} state={ready_state}",
                                                    tpdu_cmd=2,
                                                )
                                            role_state["v134_ready_ntf_sent"] = True

                                            log(
                                                "ROOM",
                                                f"LATEJOIN-v2 A110 toggle uin={requester_uin} "
                                                f"was_ready={was_ready} -> ready={ready} "
                                                f"seat={ready_seat} state={ready_state}; "
                                                "A112 sent for both Ready and Cancel",
                                            )

                                        elif app["cmd"] == TGAME_ZN_REQ_SETGAMESETTINGS:
                                            try:
                                                settings = _v143b_parse_set_game_settings_request(
                                                    app["body"]
                                                )
                                                room = (
                                                    role_state.get("v79_created_match_room")
                                                    or V150_ROOM_REGISTRY.room_for_player(
                                                        _v150_role_uin(role_state)
                                                    )
                                                )
                                                if not isinstance(room, dict) or room.get("room_id") is None:
                                                    raise RoomRegistryError(
                                                        "A11E received while player is not in a room"
                                                    )

                                                room_id = int(room["room_id"])
                                                requester_uin = _v150_role_uin(role_state)
                                                V150_ROOM_REGISTRY.require_owner(
                                                    room_id, requester_uin
                                                )

                                                # LATEJOIN-v5.1:
                                                # A11E updates lobby settings. It must NOT be used
                                                # as a round-ended signal. The previous branch
                                                # unconditionally forced started=False, which can
                                                # turn an already-running room back into an ordinary
                                                # Ready/Cancel room for late entrants.
                                                fresh_room = V150_ROOM_REGISTRY.get_room(room_id)
                                                was_started = bool(
                                                    fresh_room.get("started")
                                                    if isinstance(fresh_room, dict)
                                                    else room.get("started")
                                                )

                                                if was_started:
                                                    log(
                                                        "DS-SETTINGS",
                                                        "LATEJOIN-v5.1 ignored A11E during active match: "
                                                        f"room={room_id} uin={requester_uin} "
                                                        f"mode=0x{int(settings['mode_id']):08x} "
                                                        f"map=0x{int(settings['map_id']):04x} "
                                                        f"submode=0x{int(settings['sub_mode_id']):08x} "
                                                        f"flags=0x{int(settings['flags']):08x}; "
                                                        "preserving started=True and live DS allocation",
                                                    )
                                                else:
                                                    if V143B_DS_CONFIG.enabled:
                                                        V143B_DS_SPAWNER.prepare_lobby_settings_update(
                                                            room_id,
                                                            requester_uin,
                                                        )
                                                        V143B_DS_SPAWNER.update_lobby_settings(
                                                            room_id,
                                                            mode_id=settings["mode_id"],
                                                            map_id=settings["map_id"],
                                                            map_name=settings.get("map_string") or None,
                                                            sub_mode_id=settings["sub_mode_id"],
                                                            room_flags=settings["flags"],
                                                        )

                                                    updated_room = V150_ROOM_REGISTRY.update_settings(
                                                        room_id,
                                                        match_settings_wire=settings["match_settings_wire"],
                                                        mode_id=settings["mode_id"],
                                                        map_id=settings["map_id"],
                                                        map_string=settings["map_string"],
                                                        sub_mode_id=settings["sub_mode_id"],
                                                        flags=settings["flags"],
                                                        setting_type=settings["setting_type"],
                                                        value=settings["value"],
                                                        respawn_time=settings["respawn_time"],
                                                        recode_type=settings["recode_type"],
                                                        live_delay_sec=settings["live_delay_sec"],
                                                        no_late_join=_v150_no_late_join_from_flags(settings["flags"]),
                                                    )
                                                    _v150_sync_role_states(updated_room)
                                                    role_state["v79_created_match_room"] = updated_room
                                                    role_state.pop("v143b_ds_endpoint", None)
                                                    role_state.pop("v132_pve_afdev_handoff_sent", None)

                                                    difficulty_name = {
                                                        0x00001001: "Easy",
                                                        0x00001002: "Normal",
                                                        0x00001003: "Hard",
                                                    }.get(
                                                        int(settings["sub_mode_id"]),
                                                        f"SubModeId=0x{int(settings['sub_mode_id']):08x}",
                                                    )
                                                    log(
                                                        "DS-SETTINGS",
                                                        "A11E authoritative room settings update: "
                                                        f"room={room_id} "
                                                        f"mode=0x{int(settings['mode_id']):08x} "
                                                        f"map=0x{int(settings['map_id']):04x} "
                                                        f"submode=0x{int(settings['sub_mode_id']):08x} "
                                                        f"flags=0x{int(settings['flags']):08x} "
                                                        f"no_late_join={_v150_no_late_join_from_flags(settings['flags'])} "
                                                        f"difficulty={difficulty_name}; "
                                                        "room still waiting; will be used by lazy AFDEV spawn"
                                                        + (
                                                            f" tail={settings['tail'].hex()}"
                                                            if settings["tail"] else ""
                                                        ),
                                                    )
                                            except (ValueError, RoomRegistryError, SpawnerError) as settings_e:
                                                log(
                                                    "DS-SETTINGS",
                                                    "A11E settings update rejected: "
                                                    f"{type(settings_e).__name__}: {settings_e}; "
                                                    f"body={app['body'].hex()}",
                                                )

                                        elif app["cmd"] == TGAME_ZN_REQ_STARTMATCH:
                                            requester_uin = _v150_role_uin(role_state)
                                            authoritative_room = V150_ROOM_REGISTRY.room_for_player(
                                                requester_uin
                                            )
                                            if authoritative_room is not None:
                                                try:
                                                    V150_ROOM_REGISTRY.require_owner(
                                                        int(authoritative_room["room_id"]),
                                                        requester_uin,
                                                    )
                                                except RoomRegistryError as owner_e:
                                                    log(
                                                        "ROOM",
                                                        f"A113 StartMatch rejected requester={requester_uin}: {owner_e}",
                                                    )
                                                    continue

                                            start_type = (
                                                app["body"][0]
                                                if len(app["body"]) >= 1
                                                else None
                                            )
                                            log(
                                                label,
                                                "C2ZN_REQ_STARTMATCH v89: "
                                                f"body_len={len(app['body'])} "
                                                + (
                                                    f"start_type=0x{start_type:02x} "
                                                    if start_type is not None
                                                    else "start_type=<missing> "
                                                )
                                                + f"body={app['body'].hex()}"
                                            )

                                            rsp = _v86_build_res_start_match()
                                            _v48_send_app(
                                                conn,
                                                active_tgame_key,
                                                rsp,
                                                label,
                                                "ZN2C_RES_STARTMATCH v89 "
                                                "cmd=0xA114 result=0x8100"
                                            )

                                            # r11: hide this room from fresh A100 browsing once
                                            # startup begins, while preserving current members.
                                            room_for_start = (
                                                authoritative_room
                                                or role_state.get("v79_created_match_room")
                                                or {}
                                            )
                                            if room_for_start.get("room_id") is not None:
                                                V150_ROOM_REGISTRY.set_started(
                                                    int(room_for_start["room_id"]), True
                                                )

                                            # A114 is only the StartMatch ACK.  For Survival,
                                            # hand the stock client directly to the real AFDEV
                                            # listen server.  If A3A0 already emitted A11A, the
                                            # per-connection guard suppresses this duplicate.
                                            pve_handoff = _v132_send_pve_afdev_handoff(
                                                conn,
                                                active_tgame_key,
                                                label,
                                                role_state,
                                                reason="A113 StartMatch accepted",
                                                room=room_for_start,
                                            )

                                            if not pve_handoff:
                                                # Fail closed and undo the logical start. A114 was
                                                # already emitted (verified stock ordering), so do
                                                # not invent an unverified failure packet; instead
                                                # restore the room to a retryable waiting state and
                                                # tear down any failed/partial DS generation.
                                                mode_now = _v132_room_mode(role_state)
                                                room_id_failed = room_for_start.get("room_id")
                                                rollback_result = None
                                                if room_id_failed is not None:
                                                    try:
                                                        rollback_result = _v143b_quit_match_player(
                                                            role_state, room_for_start,
                                                            reason="A113 DS handoff failed rollback",
                                                        )
                                                    except SpawnerError as rollback_e:
                                                        log("DS-HANDOFF", f"A113 rollback warning: {rollback_e}")
                                                    try:
                                                        V150_ROOM_REGISTRY.set_started(
                                                            int(room_id_failed), False
                                                        )
                                                    except RoomRegistryError as rollback_e:
                                                        log("DS-HANDOFF", f"A113 room rollback warning: {rollback_e}")
                                                _v143b_clear_player_handoff_state(role_state)
                                                log(
                                                    "DS-HANDOFF",
                                                    "A113 dynamic AFDEV handoff failed; "
                                                    f"mode=0x{mode_now:08x}; room restored to waiting; "
                                                    f"rollback={rollback_result}; legacy fixed endpoint suppressed",
                                                )

                                        elif app["cmd"] == TGAME_ZN_REQ_JOINMATCH:
                                            # LATEJOIN-v5:
                                            # v26 disassembly proved A116 is a real compiled
                                            # TGOnlineMultiGameRoom response handler and that its
                                            # decoded payload layout matches A11A:
                                            #
                                            #   +0x00 u16 Result
                                            #   +0x02 u32 Ip
                                            #   +0x06 u16 Port
                                            #   +0x08 byte DSKey[16]
                                            #   +0x18 Domain
                                            #   +0x98 IsUseDomain
                                            #
                                            # Therefore the old 2-byte A116 ACK was malformed.
                                            # Send A116 with the same full GameServerInfo/DSInfo
                                            # body used by the already-proven A11A serializer.
                                            requester_uin = _v150_role_uin(role_state)
                                            room_now = (
                                                V150_ROOM_REGISTRY.room_for_player(requester_uin)
                                                or role_state.get("v79_created_match_room")
                                                or {}
                                            )
                                            room_id_now = room_now.get("room_id")
                                            player_mode = app["body"][0] if app["body"] else 0
                                            join_seat = int(role_state.get("v88_match_seat", 0))

                                            log(
                                                "JOINMATCH",
                                                f"LATEJOIN-v5.5 A115 accepted uin={requester_uin} "
                                                f"room={room_id_now} seat={join_seat} "
                                                f"player_mode=0x{player_mode:02x} "
                                                f"body={app['body'].hex()}; "
                                                "evaluating FULL A116 DSInfo handoff (no A11A replay)",
                                            )

                                            if room_id_now is None:
                                                log(
                                                    "JOINMATCH",
                                                    f"LATEJOIN-v5 A115 has no room for uin={requester_uin}",
                                                )
                                            else:
                                                allocation = None
                                                try:
                                                    allocation = V143B_DS_SPAWNER.allocation_for_room(
                                                        int(room_id_now)
                                                    )
                                                except Exception as exc:
                                                    log(
                                                        "DS-JOIN",
                                                        f"LATEJOIN-v5 allocation lookup failed "
                                                        f"room={room_id_now}: "
                                                        f"{type(exc).__name__}: {exc}",
                                                    )

                                                allocation_state = (
                                                    str(getattr(allocation, "state", ""))
                                                    if allocation is not None else ""
                                                )

                                                # LATEJOIN-v5.5:
                                                # Once A113 has armed the per-room UDP bridge, the
                                                # endpoint is safe to advertise even while AFDEV is
                                                # still starting. The bridge is specifically built
                                                # to register/latch additional client peers and hold
                                                # their first UE3 datagram until SESSION_READY.
                                                #
                                                # v5.4 required state==READY and silently suppressed
                                                # A116 while state==STARTING. That left the stock
                                                # A115 request unanswered and produced the client
                                                # "Server timeout does not respond" popup.
                                                joinable_states = {
                                                    "ARMED",
                                                    "STARTING",
                                                    "AFDEV_READY",
                                                    "READY",
                                                }
                                                no_late_join_now = bool(
                                                    room_now.get("started")
                                                    and room_now.get("no_late_join")
                                                )
                                                requester_already_active = bool(
                                                    allocation is not None
                                                    and requester_uin
                                                    in set(getattr(allocation, "match_players", set()) or set())
                                                )

                                                if no_late_join_now and not requester_already_active:
                                                    log(
                                                        "DS-JOIN",
                                                        f"LATEJOIN-v5.6 No Late Join enforced "
                                                        f"uin={requester_uin} room={room_id_now} "
                                                        f"state={allocation_state or '<missing>'}; "
                                                        "A115/A116 handoff suppressed",
                                                    )
                                                elif allocation is None or allocation_state not in joinable_states:
                                                    log(
                                                        "DS-JOIN",
                                                        f"LATEJOIN-v5.5 DS not joinable "
                                                        f"uin={requester_uin} room={room_id_now} "
                                                        f"state={allocation_state or '<missing>'}; A116 suppressed",
                                                    )
                                                else:
                                                    if allocation_state != "READY":
                                                        log(
                                                            "DS-JOIN",
                                                            f"LATEJOIN-v5.5 EARLY A115 accepted "
                                                            f"uin={requester_uin} room={room_id_now} "
                                                            f"state={allocation_state}; advertising armed bridge "
                                                            "now; peer UDP will be latched until AFDEV is ready",
                                                        )
                                                    handoff_host = str(allocation.public_host)
                                                    handoff_port = int(allocation.public_port)

                                                    try:
                                                        ip_value = _v143b_tdr_ipv4(handoff_host)
                                                        domain = ""
                                                        use_domain = 0
                                                    except OSError:
                                                        ip_value = 0
                                                        domain = handoff_host
                                                        use_domain = 1

                                                    # Preserve the useful v3 player-state transition.
                                                    # A112 + A11A alone was already proven insufficient,
                                                    # so the only new variable in v5 is a correctly
                                                    # serialized full A116 response.
                                                    try:
                                                        loading_room = V150_ROOM_REGISTRY.set_player_state(
                                                            requester_uin,
                                                            TGAME_PLAYERSTATE_LOADINGMATCH,
                                                            ready=False,
                                                        )
                                                        if loading_room is not None:
                                                            _v150_sync_role_states(loading_room)
                                                    except RoomRegistryError as state_e:
                                                        log(
                                                            "LATEJOIN",
                                                            f"v5 LoadingMatch registry update failed "
                                                            f"uin={requester_uin} room={room_id_now}: {state_e}",
                                                        )

                                                    role_state["v147_room_player_state"] = (
                                                        TGAME_PLAYERSTATE_LOADINGMATCH
                                                    )
                                                    role_state["v132_match_ready"] = False

                                                    loading_ntf = _latejoin_v3_build_loading_state_ntf(
                                                        join_seat
                                                    )
                                                    sent_loading = _v150_broadcast_room(
                                                        int(room_id_now),
                                                        loading_ntf,
                                                        "ZN2C_NTF_SETREADY LATEJOIN-v5.5 "
                                                        f"cmd=0xA112 seat={join_seat} "
                                                        "state=11(LOADINGMATCH)",
                                                        tpdu_cmd=2,
                                                    )
                                                    if not sent_loading:
                                                        _v48_send_app(
                                                            conn,
                                                            active_tgame_key,
                                                            loading_ntf,
                                                            label,
                                                            "ZN2C_NTF_SETREADY LATEJOIN-v5.5-fallback "
                                                            f"cmd=0xA112 seat={join_seat} "
                                                            "state=11(LOADINGMATCH)",
                                                            tpdu_cmd=2,
                                                        )

                                                    full_join_body = (
                                                        _v48_u16(ZONE_ERR_SUCC)
                                                        + _v87_build_game_server_info(
                                                            ip=int(ip_value),
                                                            port=int(handoff_port),
                                                            ds_key=TGAME_DS_KEY,
                                                            domain=str(domain),
                                                            is_use_domain=int(use_domain),
                                                        )
                                                    )
                                                    full_join_rsp = _v62_build_server_app(
                                                        TGAME_ZN_MAGIC,
                                                        TGAME_ZN_RES_JOINMATCH,
                                                        full_join_body,
                                                    )
                                                    _v48_send_app(
                                                        conn,
                                                        active_tgame_key,
                                                        full_join_rsp,
                                                        label,
                                                        "ZN2C_RES_JOINMATCH LATEJOIN-v5.5 "
                                                        "cmd=0xA116 FULL-DSINFO "
                                                        f"result=0x8100 room={int(room_id_now)} "
                                                        f"ds={handoff_host}:{handoff_port} "
                                                        f"body_len={len(full_join_body)} "
                                                        f"body={full_join_body.hex()}",
                                                    )

                                                    role_state["v143b_ds_endpoint"] = (
                                                        f"{handoff_host}:{handoff_port}"
                                                    )
                                                    role_state["v132_pve_afdev_handoff_sent"] = True
                                                    role_state["v132_pve_afdev_handoff_reason"] = (
                                                        "LATEJOIN-v5.5 full A116 DSInfo"
                                                    )
                                                    role_state["v132_pve_afdev_handoff_at"] = time.time()

                                                    log(
                                                        "LATEJOIN",
                                                        f"v5.5 full A116 published "
                                                        f"uin={requester_uin} room={room_id_now} "
                                                        f"endpoint={handoff_host}:{handoff_port} "
                                                        f"body_len={len(full_join_body)} "
                                                        "A11A_replay=NO",
                                                    )

                                                    threading.Thread(
                                                        target=_latejoin_v3_probe_ds_peer,
                                                        args=(
                                                            int(room_id_now),
                                                            int(requester_uin),
                                                        ),
                                                        name=(
                                                            f"AF-latejoin-v5-probe-"
                                                            f"{int(requester_uin)}"
                                                        ),
                                                        daemon=True,
                                                    ).start()

                                        elif app["cmd"] == TGAME_ZN_REQ_SETINMATCH:
                                            in_match = (
                                                app["body"][0]
                                                if len(app["body"]) >= 1
                                                else None
                                            )
                                            log(
                                                label,
                                                "C2ZN_REQ_SETINMATCH v108 "
                                                f"body_len={len(app['body'])} "
                                                + (
                                                    f"in_match=0x{in_match:02x} "
                                                    if in_match is not None
                                                    else "in_match=<missing> "
                                                )
                                                + f"body={app['body'].hex()}"
                                            )

                                            if in_match:
                                                # r10: this connection is now confirmed in-match; attach
                                                # its UIN to the shared DS membership without disturbing
                                                # players already using the server.
                                                try:
                                                    _v143b_mark_player_in_match(
                                                        role_state, role_state.get("v79_created_match_room")
                                                    )
                                                except SpawnerError as exc:
                                                    log("DS-CLEANUP", f"r10 A11C player tracking failed: {exc}")

                                                # LATEJOIN-v2: persist the room-visible player state.
                                                # This makes a subsequent late joiner's A105 show
                                                # already-playing members as InMatch(12), not Unready(8).
                                                try:
                                                    inmatch_room_snapshot = V150_ROOM_REGISTRY.set_player_state(
                                                        _v150_role_uin(role_state),
                                                        TGAME_PLAYERSTATE_INMATCH,
                                                        ready=False,
                                                    )
                                                    if inmatch_room_snapshot is not None:
                                                        _v150_sync_role_states(inmatch_room_snapshot)
                                                except RoomRegistryError as state_e:
                                                    log(
                                                        "LATEJOIN",
                                                        f"v2 A11C registry state update failed: {state_e}",
                                                    )
                                                # r11: use the actual shared-room seat for this UIN and
                                                # publish the A11D state transition to every room member.
                                                inmatch_seat = int(role_state.get("v88_match_seat", 0))
                                                ntf = _v108_build_ntf_set_in_match(
                                                    seat_index=inmatch_seat
                                                )
                                                room_now = role_state.get("v79_created_match_room") or {}
                                                room_id_now = room_now.get("room_id")
                                                sent_inmatch = (
                                                    _v150_broadcast_room(
                                                        room_id_now,
                                                        ntf,
                                                        "ZN2C_NTF_SETINMATCH r11-shared "
                                                        f"cmd=0xA11D seat={inmatch_seat}",
                                                    )
                                                    if room_id_now is not None
                                                    else []
                                                )
                                                if not sent_inmatch:
                                                    _v48_send_app(
                                                        conn, active_tgame_key, ntf, label,
                                                        "ZN2C_NTF_SETINMATCH v108-fallback "
                                                        f"cmd=0xA11D seat={inmatch_seat}",
                                                    )
                                            else:
                                                log(
                                                    label,
                                                    "v108: A11C requested not-in-match/zero; "
                                                    "no SetInMatch notification sent"
                                                )

                                        elif app["cmd"] == TGAME_ZN_REQ_QUITMATCH:
                                            # A117 belongs to THIS player, not the room as a whole.
                                            # The live trace confirms A118 result=0x8100. Hold A119:
                                            # its wire schema is unverified, and the prior broadcast
                                            # was followed by the other client sending its own A117.
                                            room = role_state.get("v79_created_match_room")
                                            requester_uin = _v150_role_uin(role_state)
                                            room_id_now = (
                                                int(room.get("room_id"))
                                                if isinstance(room, dict)
                                                and room.get("room_id") is not None
                                                else _v143b_room_id(role_state, room)
                                            )
                                            quit_seat = int(
                                                role_state.get("v88_match_seat", 0)
                                            )
                                            reason_byte = app["body"][0] if app["body"] else None
                                            log(
                                                label,
                                                "C2ZN_REQ_QUITMATCH r11 "
                                                f"body_len={len(app['body'])} "
                                                f"body={app['body'].hex()} "
                                                + (f"reason_byte=0x{reason_byte:02x} " if reason_byte is not None else "reason_byte=<missing> ")
                                                + f"requester={requester_uin}"
                                            )
                                            quit_result = _v143b_quit_match_player(
                                                role_state,
                                                room,
                                                reason=(
                                                    "A117 QuitMatch "
                                                    + (f"reason_byte=0x{reason_byte:02x}" if reason_byte is not None else "reason_byte=missing")
                                                ),
                                            )
                                            if (
                                                isinstance(quit_result, dict)
                                                and (
                                                    quit_result.get("ended_round")
                                                    or quit_result.get("state") == "ROUND_ENDED"
                                                )
                                                and isinstance(room, dict)
                                                and room.get("room_id") is not None
                                            ):
                                                _v143b_reset_room_after_round(
                                                    int(room["room_id"]),
                                                    "A117 QuitMatch completed previous PvE round",
                                                )
                                            # Keep the logical room ID: if this was the last match
                                            # player the spawner enters ROUND_ENDED, and the same lobby
                                            # can create a fresh DS on the next A113. If others remain,
                                            # this player can rejoin the still-running shared AFDEV.
                                            _v143b_clear_player_handoff_state(role_state)
                                            quit_rsp = _v143b_build_res_quit_match()
                                            _v48_send_app(
                                                conn,
                                                active_tgame_key,
                                                quit_rsp,
                                                label,
                                                "ZN2C_RES_QUITMATCH r11 "
                                                "cmd=0xA118 result=0x8100",
                                            )

                                            # Tell every room client which seat has left the
                                            # active match so stock room UI can clear its P state.
                                            quit_ntf = _v143b_build_ntf_quit_match(quit_seat)
                                            sent_quit = (
                                                _v150_broadcast_room(
                                                    room_id_now,
                                                    quit_ntf,
                                                    "ZN2C_NTF_QUITMATCH A119-test "
                                                    f"cmd=0xA119 seat={quit_seat}",
                                                )
                                                if room_id_now is not None
                                                else []
                                            )
                                            if not sent_quit:
                                                _v48_send_app(
                                                    conn,
                                                    active_tgame_key,
                                                    quit_ntf,
                                                    label,
                                                    "ZN2C_NTF_QUITMATCH A119-test-fallback "
                                                    f"cmd=0xA119 seat={quit_seat}",
                                                )

                                            # LATEJOIN-v5.2:
                                            # A117 only removes THIS player from the running
                                            # match. If another player is still in-match, the
                                            # round is still active and this client must return
                                            # to the room in "Join game" state, not Ready.
                                            #
                                            # The stock client accepts A119 as the transition
                                            # back into the room UI, then A11A is the already-
                                            # verified notification that exposes "Join game".
                                            # Reassert started=True from the authoritative DS
                                            # membership so room-registry drift cannot turn a
                                            # still-running match back into a waiting room.
                                            resume_join_game = False
                                            remaining_after_quit = (
                                                int(quit_result.get("remaining_match_players", 0))
                                                if isinstance(quit_result, dict)
                                                else 0
                                            )
                                            was_active_quitter = bool(
                                                quit_result.get("was_active", False)
                                                if isinstance(quit_result, dict)
                                                else False
                                            )

                                            if (
                                                room_id_now is not None
                                                and was_active_quitter
                                                and remaining_after_quit > 0
                                            ):
                                                try:
                                                    V150_ROOM_REGISTRY.set_started(
                                                        int(room_id_now), True
                                                    )
                                                except RoomRegistryError as started_e:
                                                    log(
                                                        "LATEJOIN",
                                                        "v5.2 could not reassert started=True "
                                                        f"room={room_id_now}: {started_e}",
                                                    )

                                                # Backend room state must also return this
                                                # player to unready before offering Join game.
                                                # Do NOT send A112 here: A119 has already
                                                # completed the stock quit-match UI transition.
                                                try:
                                                    quit_room_snapshot = (
                                                        V150_ROOM_REGISTRY.set_ready(
                                                            requester_uin, False
                                                        )
                                                    )
                                                    if quit_room_snapshot is not None:
                                                        _v150_sync_role_states(
                                                            quit_room_snapshot
                                                        )
                                                except RoomRegistryError as ready_e:
                                                    log(
                                                        "LATEJOIN",
                                                        "v5.2 quit-room unready sync warning "
                                                        f"uin={requester_uin} "
                                                        f"room={room_id_now}: {ready_e}",
                                                    )

                                                role_state["v132_match_ready"] = False
                                                role_state["v147_room_player_state"] = (
                                                    TGAME_PLAYERSTATE_UNREADY
                                                )

                                                resume_join_game = (
                                                    _latejoin_v2_send_running_match_a11a(
                                                        conn,
                                                        active_tgame_key,
                                                        label,
                                                        role_state,
                                                        int(room_id_now),
                                                        reason=(
                                                            "A117 returned to room while "
                                                            f"{remaining_after_quit} other "
                                                            "match player(s) remain"
                                                        ),
                                                        commit_handoff=False,
                                                    )
                                                )

                                                log(
                                                    "LATEJOIN",
                                                    "v5.2 post-A117 active-round resync "
                                                    f"uin={requester_uin} "
                                                    f"room={room_id_now} "
                                                    f"remaining_match_players="
                                                    f"{remaining_after_quit} "
                                                    f"started=True "
                                                    f"join_game_sync={resume_join_game}",
                                                )

                                            log(
                                                "DS-CLEANUP",
                                                "r11 A117 player-scoped cleanup "
                                                f"uin={requester_uin} "
                                                f"A119_recipients={sent_quit} "
                                                f"result={quit_result}",
                                            )

                                        elif app["cmd"] == TGAME_ZN_REQ_ZONECHANNEL_LIST:
                                            main_channel_id = _v75_parse_zone_channel_list_request(
                                                app["body"]
                                            )
                                            log(
                                                label,
                                                "C2ZN_REQ_ZONECHANNEL_LIST v76: "
                                                f"main_channel_id={main_channel_id} "
                                                f"body={app['body'].hex()}"
                                            )

                                            rsp = _v76_build_zone_channel_list_response(
                                                main_channel_id=main_channel_id
                                            )
                                            _v48_send_app(
                                                conn, active_tgame_key, rsp,
                                                label,
                                                "ZN2C_RES_ZONECHANNEL_LIST v76 "
                                                "cmd=0xA133 zones=1 last=1 "
                                                "subchannels=1 id=1 name='Local Subchannel' "
                                                "players=1/100 endpoint=127.0.0.1:65006"
                                            )

                                        elif app["cmd"] == TGAME_ZN_REQ_CHANNEL_PING_VALUE:
                                            padding = _v159_parse_channel_ping_request(
                                                app["body"]
                                            )
                                            log(
                                                label,
                                                "C2ZN channel timing request "
                                                f"cmd=0xA357 padding=0x{padding:08x}"
                                            )
                                            rsp = _v159_build_channel_ping_response()
                                            _v48_send_app(
                                                conn, active_tgame_key, rsp,
                                                label,
                                                "ZN2C channel timing response cmd=0xA358"
                                            )

                                        elif app["cmd"] == TGAME_ZN_REQ_MAINCHNLLIST:
                                            padding = _v73_parse_main_channel_list_request(
                                                app["body"]
                                            )
                                            log(
                                                label,
                                                "C2ZN_REQ_MAINCHNLLIST v74: "
                                                f"padding=0x{padding:08x}"
                                            )

                                            rsp = _v74_build_main_channel_list_response()
                                            _v48_send_app(
                                                conn, active_tgame_key, rsp,
                                                label,
                                                "ZN2C_RES_MAINCHNLLIST v74 "
                                                "cmd=0xA356 result=0x8100 "
                                                "count=1 id=1 type=0 (non-Rookie) "
                                                "name='Local Channel' "
                                                "players=1/100 dsa=127.0.0.1x3 wire=0100007f"
                                            )
                                            role_state["v125_mainchan_count"] = (
                                                int(role_state.get("v125_mainchan_count", 0)) + 1
                                            )

                                        elif app["cmd"] == TGAME_ZN_REQ_FRIEND_STATUS:
                                            # A303 arrives after the main lobby has initialized.
                                            # v124 sent the same Bag1 A00A about one second too
                                            # early, before the A355/A356 lobby-channel phase.
                                            a303_count = int(role_state.get("v125_a303_count", 0)) + 1
                                            role_state["v125_a303_count"] = a303_count
                                            log(
                                                label,
                                                "C2ZN_REQ_FRIENDSSTATUS v125 lobby-ready marker: "
                                                f"count={a303_count} body={app['body'].hex()} "
                                                f"mainchan_count={int(role_state.get('v125_mainchan_count',0))}"
                                            )

                                            # Fire on the second A303.  The current PH trace emits
                                            # two back-to-back A303 requests after two A355/A356
                                            # exchanges.  v126 now replays A009+A00A (not A00A alone)
                                            # because that is the complete server half of the exact
                                            # manual Bag1 click that makes the primary weapon appear.
                                            if (
                                                role_state.get("v125_bag1_refresh_armed")
                                                and int(role_state.get("v125_mainchan_count", 0)) >= 1
                                                and a303_count >= 2
                                                and not role_state.get("v126_bag1_full_transaction_sent")
                                            ):
                                                # v126: replay the ENTIRE server half of the
                                                # proven manual Bag1 click transaction.
                                                #
                                                # Live manual click sequence is:
                                                #   C->S A008 Bag1 EQUIP
                                                #   S->C A009 SUCCESS + exact operation
                                                #   S->C A00A exact operation
                                                #
                                                # v123-v125 replayed only A00A, which the live
                                                # startup UI demonstrably ignored.  A009 is the
                                                # only missing server-side message from the
                                                # known-good transaction, so send the exact pair
                                                # here without rebuilding A006.
                                                # v158: retain proven second-A303 timing but
                                                # replay the authoritative selected backpack.
                                                _v158_bag_gid = _v141_current_bag_gid()
                                                _v158_bag = _v140_find_prop(_v158_bag_gid)

                                                if (
                                                    _v158_bag is not None
                                                    and _v141_is_bag_item(
                                                        int(_v158_bag.get("item_id", 0))
                                                    )
                                                ):
                                                    _v158_bag_op = _v111_pack_prop_operation(
                                                        _r13_project_operation(
                                                            {
                                                                "operation": PROP_OP_EQUIP,
                                                                "subject_gid": _v158_bag_gid,
                                                                "target_gid": V110_BAG_MOUNT_OWNER,
                                                                "location": V109_LOC_BAG,
                                                            },
                                                            _v150_role_uin(role_state),
                                                        )
                                                    )
                                                    _v48_send_app(
                                                        conn,
                                                        active_tgame_key,
                                                        _v111_build_prop_operation_response(
                                                            _v158_bag_op
                                                        ),
                                                        label,
                                                        "ZN2C_RES_PROPOPERATION "
                                                        "v158-lobby-ready-current-bag "
                                                        "cmd=0xA009 result=0x8100 "
                                                        f"bag=0x{_v158_bag_gid:016x} "
                                                        f"item={int(_v158_bag.get('item_id', 0))}",
                                                    )
                                                    _v48_send_app(
                                                        conn,
                                                        active_tgame_key,
                                                        _v111_build_prop_operation_notification(
                                                            _v158_bag_op
                                                        ),
                                                        label,
                                                        "ZN2C_NTF_PROPOPERATION "
                                                        "v158-lobby-ready-current-bag "
                                                        "cmd=0xA00A "
                                                        f"bag=0x{_v158_bag_gid:016x} "
                                                        f"item={int(_v158_bag.get('item_id', 0))}",
                                                    )
                                                    role_state[
                                                        "v126_bag1_full_transaction_sent"
                                                    ] = True
                                                    log(
                                                        label,
                                                        "v158: lobby-ready DYNAMIC current-bag "
                                                        "transaction sent A009+A00A "
                                                        f"bag=0x{_v158_bag_gid:016x} "
                                                        f"item={int(_v158_bag.get('item_id', 0))}; "
                                                        "legacy v126 timing retained; "
                                                        "no hard-coded Bag1",
                                                    )
                                                else:
                                                    log(
                                                        label,
                                                        "v158: lobby-ready dynamic bag replay "
                                                        "skipped because current_bag_gid does not "
                                                        "resolve to an owned bag "
                                                        f"gid=0x{int(_v158_bag_gid):016x}",
                                                    )
                                            # v157b: on a Storage->lobby transition, replay the
                                            # selected bag and a complete inventory snapshot.
                                            _v157_pending = bool(
                                                role_state.get(
                                                    "v157_storage_bag_resync_pending"
                                                )
                                            )
                                            _v157_mainchan_base = int(
                                                role_state.get(
                                                    "v157_storage_bag_resync_mainchan_base",
                                                    0,
                                                )
                                            )
                                            _v157_a303_base = int(
                                                role_state.get(
                                                    "v157_storage_bag_resync_a303_base",
                                                    0,
                                                )
                                            )
                                            _v157_a303_now = int(
                                                role_state.get(
                                                    "v125_a303_count", 0
                                                )
                                            )
                                            _v157_mainchan_now = int(
                                                role_state.get(
                                                    "v125_mainchan_count", 0
                                                )
                                            )
                                            if (
                                                _v157_pending
                                                and _v157_mainchan_now > _v157_mainchan_base
                                                and _v157_a303_now >= (_v157_a303_base + 2)
                                            ):
                                                _v157_bag_gid = _v141_current_bag_gid()
                                                _v157_bag = _v140_find_prop(_v157_bag_gid)
                                                if _v157_bag is not None:
                                                    _v157_bag_op = _v111_pack_prop_operation(
                                                        _r13_project_operation(
                                                            {
                                                                "operation": PROP_OP_EQUIP,
                                                                "subject_gid": _v157_bag_gid,
                                                                "target_gid": V110_BAG_MOUNT_OWNER,
                                                                "location": V109_LOC_BAG,
                                                            },
                                                            _v150_role_uin(role_state),
                                                        )
                                                    )
                                                    _v48_send_app(
                                                        conn,
                                                        active_tgame_key,
                                                        _v111_build_prop_operation_response(
                                                            _v157_bag_op
                                                        ),
                                                        label,
                                                        "ZN2C_RES_PROPOPERATION "
                                                        "v157b-lobby-current-bag "
                                                        "cmd=0xA009 result=0x8100 "
                                                        f"bag=0x{_v157_bag_gid:016x}",
                                                    )
                                                    _v48_send_app(
                                                        conn,
                                                        active_tgame_key,
                                                        _v111_build_prop_operation_notification(
                                                            _v157_bag_op
                                                        ),
                                                        label,
                                                        "ZN2C_NTF_PROPOPERATION "
                                                        "v157b-lobby-current-bag "
                                                        "cmd=0xA00A "
                                                        f"bag=0x{_v157_bag_gid:016x}",
                                                    )
                                                    _v140_send_full_inventory(
                                                        conn,
                                                        active_tgame_key,
                                                        label,
                                                        prefix="v157b-lobby-bag-resync",
                                                        session_uin=_v150_role_uin(role_state),
                                                    )
                                                    log(
                                                        label,
                                                        "v157b: Storage->lobby current-bag "
                                                        "resync sent A009+A00A+A006 "
                                                        f"bag=0x{_v157_bag_gid:016x}",
                                                    )
                                                else:
                                                    log(
                                                        label,
                                                        "v157b: Storage->lobby resync skipped: "
                                                        f"current bag prop missing gid=0x{_v157_bag_gid:016x}",
                                                    )

                                                role_state[
                                                    "v157_storage_bag_resync_pending"
                                                ] = False
                                                role_state.pop(
                                                    "v157_storage_bag_resync_mainchan_base",
                                                    None,
                                                )
                                                role_state.pop(
                                                    "v157_storage_bag_resync_a303_base",
                                                    None,
                                                )

# v165: service A303 after the existing lobby/bag operations above.
                                            try:
                                                social_req = parse_friend_status_request(app["body"])
                                                social_uin = _v150_role_uin(role_state)
                                                social_friends = FRIENDS_SERVICE.list_friends(social_uin)
                                                social_online = _v165_online_uins()

                                                _v48_send_app(
                                                    conn,
                                                    active_tgame_key,
                                                    build_friend_status_response(
                                                        int(social_req["type"]),
                                                        list(social_req["uins"]),
                                                        social_friends,
                                                        social_online,
                                                    ),
                                                    label,
                                                    "ZN2C_RES_FRIENDSTATUS v165-real "
                                                    f"cmd=0xA304 friends={len(social_friends)} "
                                                    f"type={int(social_req['type'])}",
                                                )

                                                seeded = 0
                                                if not role_state.get("v165_social_seeded"):
                                                    # v171: do NOT replay A308 for already-persisted friends.
                                                    # A308 is an add-friend completion/message, not a login seed.
                                                    role_state["v165_social_seeded"] = True
                                                # v172: A326 is an event notification, not part of the
                                                # level-triggered A303 response. The PH client immediately re-issues
                                                # A303 after receiving A326, so sending A326 on every A303 creates a
                                                # self-sustaining refresh loop. Emit only initial state or a real
                                                # online/offline transition for this client session.
                                                _presence_state = role_state.setdefault("v172_presence_state", {})
                                                presence_sent = 0
                                                for _friend in social_friends:
                                                    _friend_uin = int(_friend["uin"])
                                                    _friend_online = bool(_friend_uin in social_online)
                                                    _previous = _presence_state.get(_friend_uin)
                                                    if _previous is None or bool(_previous) != _friend_online:
                                                        _v48_send_app(
                                                            conn,
                                                            active_tgame_key,
                                                            build_friend_loginout(
                                                                _friend_uin,
                                                                _friend_online,
                                                            ),
                                                            label,
                                                            "ZN2C_NTF_FRIENDLOGINOUT v172-edge "
                                                            f"friend={_friend_uin} "
                                                            f"online={_friend_online} "
                                                            f"type={1 if _friend_online else 2} "
                                                            f"previous={_previous}",
                                                            tpdu_cmd=2,
                                                        )
                                                        _presence_state[_friend_uin] = _friend_online
                                                        presence_sent += 1

                                                # Forget removed friends so a later re-add gets a fresh initial edge.
                                                _friend_uin_set = {int(_f["uin"]) for _f in social_friends}
                                                for _old_uin in list(_presence_state):
                                                    if int(_old_uin) not in _friend_uin_set:
                                                        _presence_state.pop(_old_uin, None)

                                                pending_req, pending_pm = _v165_deliver_pending_social(social_uin)
                                                log(
                                                    "SOCIAL",
                                                    "v165 social-ready "
                                                    f"uin={social_uin} friends={len(social_friends)} "
                                                    f"seeded={seeded} friend_requests={pending_req} "
                                                    f"private_messages={pending_pm}",
                                                )
                                            except Exception as social_e:
                                                log(
                                                    "SOCIAL",
                                                    "A303 social processing FAILED: "
                                                    f"{type(social_e).__name__}: {social_e}; "
                                                    f"body={app['body'].hex()}",
                                                )

                                        elif app["cmd"] == TGAME_ZN_REQ_ADD_FRIEND:
                                            try:
                                                social_uin = _v150_role_uin(role_state)
                                                social_name = _v150_role_nickname(role_state)
                                                req = parse_add_friend_request(app["body"])
                                                target = FRIENDS_SERVICE.find_player(
                                                    uin=int(req["respondent_uin"] or 0),
                                                    nickname=str(req["respondent_name"] or ""),
                                                )
                                                if target is None:
                                                    log(
                                                        "SOCIAL",
                                                        "A305 target not found; no fabricated failure enum sent "
                                                        f"uin={req['respondent_uin']} name={req['respondent_name']!r}",
                                                    )
                                                    continue
                                                if int(target["uin"]) == social_uin:
                                                    log("SOCIAL", f"A305 self-add ignored uin={social_uin}")
                                                    continue

                                                created = FRIENDS_SERVICE.create_friend_request(
                                                    social_uin,
                                                    int(target["uin"]),
                                                    str(req["remark"] or ""),
                                                )

                                                if created.get("already_friends"):
                                                    _v48_send_app(
                                                        conn,
                                                        active_tgame_key,
                                                        build_add_friend_result(
                                                            friend_uin=int(target["uin"]),
                                                            friend_name=str(target["nickname"]),
                                                            result=0x8301,  # SNS_ADDFRID_AGREE
                                                            msg_id=0,
                                                        ),
                                                        label,
                                                        "ZN2C_RES_ADDFRIEND v168-already-friends-agree "
                                                        f"peer={target['nickname']}({int(target['uin'])})",
                                                    )
                                                elif created.get("opposite_pending"):
                                                    proposer = FRIENDS_SERVICE.get_player_identity(int(created["from_uin"]))
                                                    if proposer is not None:
                                                        _v48_send_app(
                                                            conn,
                                                            active_tgame_key,
                                                            build_friend_invite(
                                                                request_id=int(created["request_id"]),
                                                                proposer_uin=int(created["from_uin"]),
                                                                proposer_name=str(proposer["nickname"]),
                                                                remark=str(created.get("remark") or ""),
                                                                msg_id=int(created.get("msg_id") or created["request_id"]),
                                                            ),
                                                            label,
                                                            "ZN2C_REQ_ADDFRIEND v165-opposite-pending "
                                                            f"request_id={int(created['request_id'])}",
                                                        )
                                                else:
                                                    invite = build_friend_invite(
                                                        request_id=int(created["request_id"]),
                                                        proposer_uin=social_uin,
                                                        proposer_name=social_name,
                                                        remark=str(created.get("remark") or ""),
                                                        msg_id=int(created.get("msg_id") or created["request_id"]),
                                                    )
                                                    delivered = _v150_send_online(
                                                        int(target["uin"]),
                                                        invite,
                                                        "ZN2C_REQ_ADDFRIEND v165-real "
                                                        f"request_id={int(created['request_id'])} "
                                                        f"from={social_name}({social_uin})",
                                                    )
                                                    log(
                                                        "SOCIAL",
                                                        "A305 friend request persisted "
                                                        f"id={int(created['request_id'])} from={social_uin} "
                                                        f"to={int(target['uin'])} delivered_now={delivered}",
                                                    )
                                            except Exception as social_e:
                                                log(
                                                    "SOCIAL",
                                                    "A305 FAILED: "
                                                    f"{type(social_e).__name__}: {social_e}; "
                                                    f"body={app['body'].hex()}",
                                                )

                                        elif app["cmd"] == TGAME_ZN_C2S_RES_ADD_FRIEND:
                                            try:
                                                social_uin = _v150_role_uin(role_state)
                                                rsp = parse_add_friend_client_response(app["body"])
                                                accepted = int(rsp["result"]) == 0x8301  # PH A307: live Accept button decision code
                                                request_row = FRIENDS_SERVICE.resolve_friend_request(
                                                    int(rsp["request_id"]),
                                                    social_uin,
                                                    accepted,
                                                )
                                                proposer_uin = int(request_row["from_uin"])

                                                if accepted:
                                                    proposer = FRIENDS_SERVICE.get_player_identity(proposer_uin)
                                                    acceptor = FRIENDS_SERVICE.get_player_identity(social_uin)
                                                    if proposer is None or acceptor is None:
                                                        raise FriendsError("accepted friend request identity disappeared")
                                                    msg_id = int(request_row.get("msg_id") or rsp["request_id"])

                                                    _v48_send_app(
                                                        conn,
                                                        active_tgame_key,
                                                        build_add_friend_result(
                                                            friend_uin=proposer_uin,
                                                            friend_name=str(proposer["nickname"]),
                                                            result=0x8301,  # SNS_ADDFRID_AGREE
                                                            msg_id=msg_id,
                                                        ),
                                                        label,
                                                        "ZN2C_RES_ADDFRIEND v168-agree-self "
                                                        f"peer={proposer['nickname']}({proposer_uin})",
                                                    )
                                                    _v150_send_online(
                                                        proposer_uin,
                                                        build_add_friend_result(
                                                            friend_uin=social_uin,
                                                            friend_name=str(acceptor["nickname"]),
                                                            result=0x8301,  # SNS_ADDFRID_AGREE
                                                            msg_id=msg_id,
                                                        ),
                                                        "ZN2C_RES_ADDFRIEND v168-agree-peer "
                                                        f"peer={acceptor['nickname']}({social_uin})",
                                                    )

                                                log(
                                                    "SOCIAL",
                                                    "A307 friend request resolved "
                                                    f"id={int(rsp['request_id'])} acceptor={social_uin} "
                                                    f"accepted={accepted} result=0x{int(rsp['result']):04x}",
                                                )
                                            except Exception as social_e:
                                                log(
                                                    "SOCIAL",
                                                    "A307 FAILED: "
                                                    f"{type(social_e).__name__}: {social_e}; "
                                                    f"body={app['body'].hex()}",
                                                )

                                        elif app["cmd"] == TGAME_ZN_REQ_DEL_FRIEND:
                                            try:
                                                social_uin = _v150_role_uin(role_state)
                                                friend_uin = parse_delete_friend_request(app["body"])
                                                existed = FRIENDS_SERVICE.delete_friendship(social_uin, int(friend_uin))
                                                _v48_send_app(
                                                    conn,
                                                    active_tgame_key,
                                                    build_delete_friend_response(int(friend_uin), SNS_ERR_SUCC),
                                                    label,
                                                    "ZN2C_RES_DELFRIEND v165-real "
                                                    f"cmd=0xA30A friend_uin={int(friend_uin)}",
                                                )
                                                log(
                                                    "SOCIAL",
                                                    f"A309 friendship deleted uin={social_uin} "
                                                    f"friend={int(friend_uin)} existed={existed}",
                                                )
                                            except Exception as social_e:
                                                log(
                                                    "SOCIAL",
                                                    "A309 FAILED: "
                                                    f"{type(social_e).__name__}: {social_e}; "
                                                    f"body={app['body'].hex()}",
                                                )

                                        elif app["cmd"] == TGAME_ZN_REQ_QUERY_FRIEND:
                                            try:
                                                query = parse_query_friend_request(app["body"])
                                                qtype = int(query["query_type"])
                                                qu = int(query["query_uin"] or 0)
                                                qc = str(query["query_content"] or "")

                                                if qtype == 2:
                                                    target = FRIENDS_SERVICE.find_player(nickname=qc)
                                                else:
                                                    target_uin = qu
                                                    if not target_uin and qc.strip().isdigit():
                                                        target_uin = int(qc.strip())
                                                    target = FRIENDS_SERVICE.find_player(uin=target_uin) if target_uin else None

                                                if target is None:
                                                    log(
                                                        "SOCIAL",
                                                        "A30F Find Player unresolved; no unverified not-found A310 sent "
                                                        f"type={qtype} query_uin={qu} content={qc!r}",
                                                    )
                                                else:
                                                    out = build_query_friend_response(
                                                        target,
                                                        result=0x8100,  # QueryFriend stock-UI success
                                                        privacy_flags=EPTE_ADD_BY_ALL,
                                                    )
                                                    _v48_send_app(
                                                        conn,
                                                        active_tgame_key,
                                                        out,
                                                        label,
                                                        "ZN2C_RES_FINDFRIEND v166-ui-success "
                                                        f"cmd=0xA310 uin={int(target['uin'])} "
                                                        f"nickname={target['nickname']!r} "
                                                        f"exp={int(target.get('experience') or 0)} "
                                                        "privacy_flags=0x0001",
                                                    )
                                                    log(
                                                        "SOCIAL",
                                                        "A30F Find Player resolved -> A310 v166 UI-success response sent "
                                                        f"type={qtype} query_uin={qu} content={qc!r} resolved={target}",
                                                    )
                                            except Exception as social_e:
                                                log(
                                                    "SOCIAL",
                                                    "A30F FAILED: "
                                                    f"{type(social_e).__name__}: {social_e}; "
                                                    f"body={app['body'].hex()}",
                                                )

                                        elif app["cmd"] in (0xA313, 0xA315, 0xA317):
                                            _v177_friend_action(conn, active_tgame_key, label, role_state, app)

                                        elif app["cmd"] == TGAME_ZN_REQ_CHAT_P2P:
                                            try:
                                                social_uin = _v150_role_uin(role_state)
                                                social_name = _v150_role_nickname(role_state)
                                                chat = parse_chat_p2p_request(app["body"])
                                                target = FRIENDS_SERVICE.find_player(
                                                    uin=int(chat["recipient_uin"] or 0),
                                                    nickname=str(chat["recipient_name"] or ""),
                                                )
                                                if target is None:
                                                    raise FriendsError("chat recipient does not exist")

                                                stored = FRIENDS_SERVICE.store_private_message(
                                                    social_uin,
                                                    int(target["uin"]),
                                                    int(chat["chat_type"]),
                                                    str(chat["message"]),
                                                )
                                                ntf = build_chat_p2p_notify(
                                                    int(chat["chat_type"]),
                                                    str(chat["message"]),
                                                    sender_uin=social_uin,
                                                    sender_name=social_name,
                                                )
                                                delivered = _v150_send_online(
                                                    int(target["uin"]),
                                                    ntf,
                                                    "ZN2C_NTF_CHATP2P v165-real "
                                                    f"message_id={int(stored['message_id'])} "
                                                    f"from={social_name}({social_uin})",
                                                )
                                                if delivered:
                                                    FRIENDS_SERVICE.mark_private_message_delivered(int(stored["message_id"]))

                                                log(
                                                    "SOCIAL",
                                                    "A405 private chat "
                                                    f"id={int(stored['message_id'])} from={social_uin} "
                                                    f"to={int(target['uin'])} delivered_now={delivered}",
                                                )
                                            except Exception as social_e:
                                                log(
                                                    "SOCIAL",
                                                    "A405 FAILED: "
                                                    f"{type(social_e).__name__}: {social_e}; "
                                                    f"body={app['body'].hex()}",
                                                )

                                        elif app["cmd"] == TGAME_ZN_NTF_READ_OFFLINE_MSG:
                                            try:
                                                _read = parse_read_offline_message_notice(app["body"])
                                                log(
                                                    "SOCIAL",
                                                    "AB03 NtfReadOfflineMessage v171 "
                                                    f"uin={_v150_role_uin(role_state)} "
                                                    f"count={int(_read['count'])} "
                                                    f"msg_ids={list(_read['msg_ids'])}",
                                                )
                                            except Exception as social_e:
                                                log(
                                                    "SOCIAL",
                                                    "AB03 NtfReadOfflineMessage FAILED: "
                                                    f"{type(social_e).__name__}: {social_e}; "
                                                    f"body={app['body'].hex()}",
                                                )

                                        elif app["cmd"] == TGAME_ZN_REQ_PLAYER_EXP:
                                            try:
                                                exp_req = parse_player_exp_request(app["body"])
                                                exp_uins = [int(v) for v in exp_req["uins"]]
                                                exp_values = []
                                                for _exp_uin in exp_uins:
                                                    _identity = FRIENDS_SERVICE.get_player_identity(
                                                        _exp_uin
                                                    )
                                                    exp_values.append(
                                                        int((_identity or {}).get("experience") or 0)
                                                    )

                                                _v48_send_app(
                                                    conn,
                                                    active_tgame_key,
                                                    build_player_exp_response(
                                                        int(exp_req["type"]),
                                                        exp_uins,
                                                        exp_values,
                                                    ),
                                                    label,
                                                    "ZN2C_RES_PLAYEREXP v170-static "
                                                    f"cmd=0xA33B type={int(exp_req['type'])} "
                                                    f"uins={exp_uins} exps={exp_values}",
                                                )
                                                log(
                                                    "SOCIAL",
                                                    "A33A GetPlayerExps v170-static "
                                                    f"requester={_v150_role_uin(role_state)} "
                                                    f"type={int(exp_req['type'])} "
                                                    f"uins={exp_uins} exps={exp_values}",
                                                )
                                            except Exception as social_e:
                                                log(
                                                    "SOCIAL",
                                                    "A33A GetPlayerExps FAILED: "
                                                    f"{type(social_e).__name__}: {social_e}; "
                                                    f"body={app['body'].hex()}",
                                                )

                                        elif app["cmd"] == TGAME_ZN_REQ_STARTROOMALLOC:
                                            requester_uin = _v150_role_uin(role_state)
                                            allocation_room = V150_ROOM_REGISTRY.room_for_player(
                                                requester_uin
                                            )
                                            if allocation_room is not None:
                                                try:
                                                    V150_ROOM_REGISTRY.require_owner(
                                                        int(allocation_room["room_id"]),
                                                        requester_uin,
                                                    )
                                                except RoomRegistryError as owner_e:
                                                    log(
                                                        "ROOM",
                                                        f"A3A0 StartRoomAlloc rejected requester={requester_uin}: {owner_e}",
                                                    )
                                                    continue

                                            ra = _v72_parse_start_room_alloc(app["body"])
                                            log(
                                                label,
                                                "C2ZN_REQ_STARTROOMALLOC v72 decoded: "
                                                f"uin={ra['uin']} "
                                                f"mode=0x{ra['mode_id']:08x} "
                                                f"match_map=0x{ra['match_map_id']:04x} "
                                                f"hard={ra['hard_level']} "
                                                f"map_count={ra['map_count']} "
                                                f"maps={[hex(x) for x in ra['maps']]} "
                                                f"match_raw={ra['match'].hex()} "
                                                f"tail={ra['tail'].hex()}"
                                            )

                                            # First acknowledge the request, then publish the
                                            # queue-entry notification.  This intentionally stops
                                            # short of A3A5 (match found / DS assignment) so the
                                            # next client transition can be observed cleanly.
                                            rsp = _v72_build_start_room_alloc_success()
                                            _v48_send_app(
                                                conn, active_tgame_key, rsp,
                                                label,
                                                "ZN2C_RES_STARTROOMALLOC v72-roomalloc-accept "
                                                "cmd=0xA3A2 result=0x8100"
                                            )

                                            ntf = _v72_build_enter_room_alloc_success()
                                            _v48_send_app(
                                                conn, active_tgame_key, ntf,
                                                label,
                                                "ZN2C_NTF_ENTERROOMALLOC v72-roomalloc-accept "
                                                "cmd=0xA3A1 result=0x8100"
                                            )

                                            # v132: this PH build's Match -> Start button is
                                            # already proven to emit A3A0.  Once the allocation
                                            # request is accepted, publish the stock A11A DSInfo
                                            # directly to the AFDEV UE3 listen server for PVE.
                                            # Do not wait for the abandoned A3A5 reconstruction.
                                            roomalloc_handoff = _v132_send_pve_afdev_handoff(
                                                conn,
                                                active_tgame_key,
                                                label,
                                                role_state,
                                                reason="A3A0 StartRoomAlloc accepted",
                                                room=allocation_room,
                                                start_settings=ra,
                                                mode_id=ra.get("mode_id"),
                                            )
                                            if not roomalloc_handoff:
                                                room_for_alloc = (
                                                    allocation_room
                                                    or role_state.get("v79_created_match_room")
                                                    or {}
                                                )
                                                try:
                                                    _v143b_quit_match_player(
                                                        role_state, room_for_alloc,
                                                        reason="A3A0 DS handoff failed rollback",
                                                    )
                                                except SpawnerError as rollback_e:
                                                    log("DS-HANDOFF", f"A3A0 rollback warning: {rollback_e}")
                                                _v143b_clear_player_handoff_state(role_state)
                                                log(
                                                    "DS-HANDOFF",
                                                    "A3A0 accepted but dynamic DS handoff failed; "
                                                    "partial match state rolled back; no dead endpoint advertised",
                                                )

                                        elif app["cmd"] == TGAME_ZN_REQ_USE_CARD:
                                            try:
                                                func_type, sub_func_type = (
                                                    _v160_parse_use_card(app["body"])
                                                )
                                            except ValueError as use_e:
                                                log(
                                                    "MALL-ITEM",
                                                    f"A347 UseCard rejected: {use_e}",
                                                )
                                                use_result = ZONE_FAIL_NOACCOUNTEXIST
                                                use_action = "malformed request"
                                                use_prop = None
                                            else:
                                                use_prop, use_action = (
                                                    _v160_activate_known_function_card(
                                                        func_type, sub_func_type
                                                    )
                                                )
                                                use_result = (
                                                    ZONE_ERR_SUCC
                                                    if use_prop is not None
                                                    else ZONE_FAIL_NOACCOUNTEXIST
                                                )

                                            _v48_send_app(
                                                conn,
                                                active_tgame_key,
                                                _v160_build_result_only_response(
                                                    TGAME_ZN_RES_USE_CARD,
                                                    use_result,
                                                ),
                                                label,
                                                "ZN2C_RES_USECARD v160 "
                                                f"cmd=0xA348 result=0x{use_result:04x}",
                                            )
                                            if use_prop is not None:
                                                _v140_send_full_inventory(
                                                    conn,
                                                    active_tgame_key,
                                                    label,
                                                    prefix="v160-use-card",
                                                    session_uin=_v150_role_uin(role_state),
                                                )
                                            log(
                                                "MALL-ITEM",
                                                "v160 A347 UseCard "
                                                f"FunctionType={locals().get('func_type', -1)} "
                                                f"SubFunctionType={locals().get('sub_func_type', -1)} "
                                                f"result=0x{use_result:04x} => {use_action}",
                                            )

                                        elif app["cmd"] == TGAME_ZN_REQ_CLEAR_MATCH_RECORD:
                                            card = _v160_consume_inventory_item(
                                                V160_CLEAR_RECORD_CARD_ITEM_ID,
                                                "F303-clear-match-record-card",
                                            )
                                            clear_result = (
                                                ZONE_ERR_SUCC
                                                if card is not None
                                                else ZONE_FAIL_NOACCOUNTEXIST
                                            )
                                            _v48_send_app(
                                                conn,
                                                active_tgame_key,
                                                _v160_build_result_only_response(
                                                    TGAME_ZN_RES_CLEAR_MATCH_RECORD,
                                                    clear_result,
                                                ),
                                                label,
                                                "ZN2C_RES_CLEARMATCHRECORD v160 "
                                                f"cmd=0xF304 result=0x{clear_result:04x}",
                                            )
                                            if card is not None:
                                                _v140_send_full_inventory(
                                                    conn,
                                                    active_tgame_key,
                                                    label,
                                                    prefix="v160-clear-record-card",
                                                    session_uin=_v150_role_uin(role_state),
                                                )
                                            log(
                                                "MALL-ITEM",
                                                "v160 F303 ClearMatchRecordData "
                                                f"card_item={V160_CLEAR_RECORD_CARD_ITEM_ID} "
                                                f"consumed={card is not None}",
                                            )

                                        elif app["cmd"] == TGAME_ZN_REQ_CLEAR_MATCH_WINLOSE:
                                            card = _v160_consume_inventory_item(
                                                V160_CLEAR_WINLOSE_CARD_ITEM_ID,
                                                "F305-clear-winlose-card",
                                            )
                                            clear_result = (
                                                ZONE_ERR_SUCC
                                                if card is not None
                                                else ZONE_FAIL_NOACCOUNTEXIST
                                            )
                                            _v48_send_app(
                                                conn,
                                                active_tgame_key,
                                                _v160_build_result_only_response(
                                                    TGAME_ZN_RES_CLEAR_MATCH_WINLOSE,
                                                    clear_result,
                                                ),
                                                label,
                                                "ZN2C_RES_CLEARMATCHWINLOSE v160 "
                                                f"cmd=0xF306 result=0x{clear_result:04x}",
                                            )
                                            if card is not None:
                                                _v140_send_full_inventory(
                                                    conn,
                                                    active_tgame_key,
                                                    label,
                                                    prefix="v160-clear-winlose-card",
                                                    session_uin=_v150_role_uin(role_state),
                                                )
                                            log(
                                                "MALL-ITEM",
                                                "v160 F305 ClearMatchWinLoseData "
                                                f"card_item={V160_CLEAR_WINLOSE_CARD_ITEM_ID} "
                                                f"consumed={card is not None}",
                                            )

                                        elif app["cmd"] == TGAME_ZN_REQ_CHANGE_NICKNAME:
                                            try:
                                                new_nickname = _nick_v1_parse_change_nickname(
                                                    app["body"]
                                                )
                                            except ValueError as nick_e:
                                                log(
                                                    "NICKNAME",
                                                    "F301 rejected locally: "
                                                    f"{nick_e}; body={app['body'].hex()}",
                                                )
                                            else:
                                                old_nickname = _v150_role_nickname(role_state)
                                                uin_now = _v150_role_uin(role_state)
                                                login_name_now = (
                                                    str(role_state.get("login_name") or "").strip()
                                                    or _r12_login_for_uid(uin_now)
                                                    or PLAYER_DB.login_for_uin(uin_now)
                                                )

                                                try:
                                                    # Claim first. Never tell the stock client a
                                                    # rename succeeded if persistence/uniqueness
                                                    # failed underneath it.
                                                    PLAYER_DB.claim_nickname(
                                                        uin_now,
                                                        new_nickname,
                                                    )
                                                except Exception as nick_db_e:
                                                    log(
                                                        "NICKNAME",
                                                        "F301 nickname claim REJECTED: "
                                                        f"uin={uin_now} "
                                                        f"old={old_nickname!r} "
                                                        f"new={new_nickname!r} "
                                                        f"{type(nick_db_e).__name__}: {nick_db_e}",
                                                    )
                                                    fail_response = (
                                                        _nick_v1_build_change_nickname_response(
                                                            new_nickname,
                                                            result=ZONE_FAIL_NOACCOUNTEXIST,
                                                        )
                                                    )
                                                    _v48_send_app(
                                                        conn,
                                                        active_tgame_key,
                                                        fail_response,
                                                        label,
                                                        "ZN2C_RES_CHANGE_NICKNAME v26 "
                                                        "cmd=0xF302 result=0x0104 "
                                                        "nickname-claim-rejected",
                                                    )
                                                    continue

                                                response = _nick_v1_build_change_nickname_response(
                                                    new_nickname
                                                )
                                                _v48_send_app(
                                                    conn,
                                                    active_tgame_key,
                                                    response,
                                                    label,
                                                    "ZN2C_RES_CHANGE_NICKNAME v26 "
                                                    "cmd=0xF302 result=0x8100 "
                                                    f"old={old_nickname!r} new={new_nickname!r}",
                                                )

                                                role_state["nickname"] = new_nickname
                                                with _V150_ZONE_LOCK:
                                                    session = _V150_ZONE_SESSIONS.get(uin_now)
                                                    if session is not None:
                                                        session["nickname"] = new_nickname

                                                if login_name_now:
                                                    role_state["login_name"] = login_name_now
                                                log(
                                                    "NICKNAME",
                                                    "SQLite nickname atomically persisted: "
                                                    f"uin={uin_now} "
                                                    f"login={login_name_now!r} "
                                                    f"nickname={new_nickname!r}",
                                                )

                                                if V143B_DS_CONFIG.enabled:
                                                    try:
                                                        nick_alloc = (
                                                            V143B_DS_SPAWNER.set_owner_nickname(
                                                                uin_now, new_nickname
                                                            )
                                                        )
                                                        if nick_alloc is not None:
                                                            log(
                                                                "NICKNAME",
                                                                "F301 propagated to reserved DS room: "
                                                                f"room={nick_alloc.room_id} "
                                                                f"nickname={new_nickname!r}",
                                                            )
                                                    except SpawnerError as nick_ds_e:
                                                        log(
                                                            "NICKNAME",
                                                            "F301 DS nickname propagation warning: "
                                                            f"{nick_ds_e}",
                                                        )

                                                rename_card = _v160_consume_inventory_item(
                                                    V160_RENAME_CARD_ITEM_ID,
                                                    "F301-rename-card-consume",
                                                )
                                                if rename_card is not None:
                                                    _v140_send_full_inventory(
                                                        conn,
                                                        active_tgame_key,
                                                        label,
                                                        prefix="v160-rename-card",
                                                        session_uin=uin_now,
                                                    )

                                                log(
                                                    "NICKNAME",
                                                    "F301 handled with atomic nickname claim: "
                                                    f"uin={uin_now} old={old_nickname!r} "
                                                    f"new={new_nickname!r}; "
                                                    "runtime + SQLite identity committed; "
                                                    f"Rename Card consumed={rename_card is not None}",
                                                )

                                        else:
                                            log(
                                                label,
                                                "UNHANDLED C2ZN REQUEST "
                                                f"cmd=0x{app['cmd']:04x} "
                                                f"{_v139_unhandled_text(app['cmd'])} "
                                                f"body={app['body'].hex()}"
                                            )
                                    else:
                                        log(
                                            label,
                                            f"Unknown application magic "
                                            f"0x{app['magic']:04x}"
                                        )

                                except Exception as app_e:
                                    if label.upper() == "DS-TCP":
                                        log(
                                            label,
                                            "v95 DS DECRYPTED NONSTANDARD PAYLOAD: "
                                            f"{type(app_e).__name__}: {app_e}; "
                                            f"plain_len={len(plain_now)} "
                                            f"plain={_clan_debug_hex(plain_now)}"
                                        )
                                    else:
                                        log(
                                            label,
                                            f"TGame application parse/dispatch FAILED: "
                                            f"{type(app_e).__name__}: {app_e}; "
                                            f"plain={_clan_debug_hex(plain_now)}"
                                        )
                        except Exception as e:
                            log(
                                label,
                                f"TGame mode3 follow-up decode FAILED: {e}; raw={extra.hex()}"
                            )
                    elif mode_now == 4:
                        for line in tgame_decode_cmd09(extra, tgame_mode4_key):
                            log(label, line)
                    else:
                        log(label, f"TGame follow-up received under mode={mode_now}: {extra.hex()}")
                elif role_state.get("session_key"):
                    for line in role_decode_synack(extra, role_state["session_key"]):
                        log(label, line)

    except ConnectionResetError:
        log(label, "Connection reset by client")

    except Exception as e:
        log(
            label,
            f"ERROR: {type(e).__name__}: {e}"
        )

    finally:
        # r10 fail-safe: a ZONE disconnect belongs to one player. Remove only
        # that UIN from room/match membership. The shared DS remains alive while
        # another in-match player exists; the last player triggers cleanup.
        if (
            str(label).upper() == "ZONE"
            and not SERVER_SHUTTING_DOWN.is_set()
        ):
            try:
                rs = locals().get("role_state")
                if isinstance(rs, dict):
                    disconnect_uin = _v150_role_uin(rs)
                    shared_disconnect = V150_ROOM_REGISTRY.leave_room(disconnect_uin)
                    if shared_disconnect and shared_disconnect.get("room"):
                        _v150_sync_role_states(shared_disconnect["room"])
                        disconnect_ntf = _v138_build_ntf_leave_match_room(
                            seat_index=int(shared_disconnect["removed"].get("seat_index", 0)),
                            leave_reason=0,
                        )
                        _v150_broadcast_room(
                            shared_disconnect["room_id"],
                            disconnect_ntf,
                            "ZN2C_NTF_LEAVEMATCHROOM r11 disconnect peer-update",
                            exclude=(disconnect_uin,),
                        )
                    room = rs.get("v79_created_match_room")
                    if isinstance(room, dict) and room.get("room_id") is not None:
                        disconnect_result = _v143b_remove_room_player(
                            rs,
                            room,
                            reason="ZONE TCP disconnected/handler exited",
                            authoritative_new_owner=(
                                shared_disconnect.get("new_owner_uin")
                                if shared_disconnect else None
                            ),
                        )
                        rs.pop("v143b_ds_endpoint", None)
                        rs.pop("v132_pve_afdev_handoff_sent", None)
                        log(
                            "DS-CLEANUP",
                            "r10 ZONE disconnect player-scoped cleanup "
                            f"uin={int(rs.get('uin') or 10001)} result={disconnect_result}",
                        )
            except Exception as cleanup_e:
                log(
                    "DS-CLEANUP",
                    f"r10 ZONE disconnect cleanup failed: {type(cleanup_e).__name__}: {cleanup_e}",
                )
            try:
                rs = locals().get("role_state")
                if isinstance(rs, dict):
                    _v150_unregister_zone_session(rs, conn)
            except Exception as session_cleanup_e:
                log(
                    "ZONE",
                    "online-session cleanup failed: "
                    f"{type(session_cleanup_e).__name__}: {session_cleanup_e}",
                )
        try:
            conn.close()
        except Exception:
            pass


def tdr_u8(v):
    return struct.pack(">B", v)

def tdr_u16(v):
    return struct.pack(">H", v)

def tdr_u32(v):
    return struct.pack(">I", v)

def tdr_string(s):
    b = s.encode("ascii") + b"\x00"
    return tdr_u32(len(b)) + b
def build_dir_root():
    return build_dir_category(
        0x00000000,
        0x00000000,
        "Root",
        0                    # root flag stays 0
    )
def build_dir_leaf():
    node = bytearray()

    node += tdr_u16(1)
    node += tdr_u32(0x01010101)      # LeafID
    node += tdr_u32(0x01010100)      # ParentID

    node += tdr_u32(3)               # Flag: Wnd = 3  <-- IMPORTANT

    node += tdr_string("Assault Fire Local")
    node += tdr_u32(0)               # BitmapMask
    node += tdr_string("tcp://127.0.0.1:65005")
    node += tdr_string("1.0.0.24")
    node += tdr_u32(3)               # CltAttr
    node += tdr_u32(0)               # CltAttr1
    node += tdr_string("")            # AppStaticAttr
    node += tdr_u8(1)                 # Status
    # Dir.dll PlayerSelectedServer treats DynamicInfo.ConnectUrl as:
    #     host:decimal_port;
    # It extracts text before ':' as host and text between ':' and ';' as port.
    # Using "tcp://..." makes the first ':' belong to "tcp:" and leaves the
    # numeric-port parse empty -> atoi("") == 0 -> CreateInitConnectionEx port 0.
    node += tdr_string("127.0.0.1:65005;")
    node += tdr_u16(0)               # AppDynamicAttr

    return bytes(node)

def build_dir_category(cid, pid, name, flag):
    node = bytearray()

    node += tdr_u16(0)
    node += tdr_u32(cid)
    node += tdr_u32(pid)
    node += tdr_u32(flag)

    node += tdr_string(name)
    node += tdr_u32(0)
    node += tdr_u32(0)
    node += tdr_string("")
    node += tdr_u8(1)
    node += tdr_u16(0)

    return bytes(node)
def handle_dir(conn, addr):
    try:
        req = recv_exact(conn, 26, timeout=10.0)

        log(
            "DIR",
            f"Connected from {addr} ({len(req)}B)"
        )

        if len(req) != 26:
            log("DIR", f"Bad request length: {len(req)}")
            return

        log("DIR", f"RX: {req.hex()}")

        # Minimal GetDirTree_Rsp body:
        #
        # u16 NodeCount = 0
        # remaining packing/data fields = 0
        #
        root = build_dir_root()

        category = build_dir_category(
            0x01010100,
            0x00000000,
            "Assault Fire Local",
            3                       # <-- category Flag = 3
        )

        leaf = build_dir_leaf()

        node_data = root + category + leaf

        body = (
            tdr_u16(3) +
            b"\x81" +
            tdr_u16(3) +
            tdr_u16(len(node_data)) +
            node_data
        )

        log(
            "DIR",
            f"Category={len(category)}B Leaf={len(leaf)}B "
            f"NodeData={len(node_data)}B"
        )

        # Copy request header so ServiceId, Seq, ISP, Province
        # stay exactly what the client sent.
        resp = bytearray(req)

        # BodyLen
        resp[4:8] = len(body).to_bytes(4, "big")

        # MsgID:
        # 0x1771 = GetDirTree_Req
        # 0x1772 = GetDirTree_Rsp
        resp[12:16] = (0x1772).to_bytes(4, "big")

        # ErrorCode = success
        resp[20:24] = (0).to_bytes(4, "big")

        packet = bytes(resp) + body

        log(
            "DIR",
            f"TX ({len(packet)}B): {_short_hex(packet)}"
        )

        conn.sendall(packet)

        # Keep it alive briefly so we can see what client does next.
        conn.settimeout(5.0)

        try:
            follow = conn.recv(4096)

            if follow:
                log(
                    "DIR",
                    f"FOLLOW-UP ({len(follow)}B): {follow.hex()}"
                )
            else:
                log("DIR", "Client closed connection")

        except socket.timeout:
            log("DIR", "No follow-up within 5 sec")

    except Exception as e:
        log("DIR", f"ERROR: {type(e).__name__}: {e}")

    finally:
        try:
            conn.close()
        except Exception:
            pass
# ---------------------------------------------------------------------------
# v91 Dedicated-server UDP probe
# ---------------------------------------------------------------------------

def _v96_ds_udp_decrypt(data, key=TGAME_DS_KEY):
    """Decrypt the live Assault Fire DS UDP wrapper.

    Verified from v95 traffic:
        u32_le cleartext_byte_count
        AES-128-ECB(zero_pad(UE3_packet, 16))
    """
    if len(data) < 20:
        raise ValueError(f"short DS UDP datagram: {len(data)}B")

    clear_len = struct.unpack_from("<I", data, 0)[0]
    enc = data[4:]

    if len(enc) % 16:
        raise ValueError(f"ciphertext is not AES block aligned: {len(enc)}B")
    if clear_len < 1 or clear_len > len(enc):
        raise ValueError(
            f"bad clear_len={clear_len} ciphertext={len(enc)}B"
        )

    dec = Cipher(
        algorithms.AES(bytes(key)),
        modes.ECB(),
        backend=default_backend(),
    ).decryptor()
    padded = dec.update(enc) + dec.finalize()
    return padded[:clear_len], padded


def _v96_ds_udp_encrypt(plain, key=TGAME_DS_KEY):
    """Inverse of _v96_ds_udp_decrypt()."""
    plain = bytes(plain)
    if not plain:
        raise ValueError("empty UE3 packet")

    padded = plain + (b"\x00" * ((-len(plain)) & 0x0F))

    enc = Cipher(
        algorithms.AES(bytes(key)),
        modes.ECB(),
        backend=default_backend(),
    ).encryptor()
    ciphertext = enc.update(padded) + enc.finalize()
    return struct.pack("<I", len(plain)) + ciphertext


def _v96_bits_from_bytes(data):
    return [
        (b >> bit) & 1
        for b in bytes(data)
        for bit in range(8)
    ]


def _v96_bits_to_bytes(bits):
    out = bytearray((len(bits) + 7) // 8)
    for i, bit in enumerate(bits):
        if bit:
            out[i >> 3] |= 1 << (i & 7)
    return bytes(out)


def _v96_read_bits(bits, pos, count):
    if pos + count > len(bits):
        raise ValueError(
            f"bitstream truncated at {pos}: need {count}, "
            f"have {len(bits)-pos}"
        )
    value = 0
    for i in range(count):
        value |= (bits[pos + i] & 1) << i
    return value, pos + count


def _v96_read_int(bits, pos, maximum):
    """UE3 packet-framing SerializeInt/ReadInt (Mask < Max)."""
    value = 0
    mask = 1
    while mask < maximum:
        bit, pos = _v96_read_bits(bits, pos, 1)
        if bit:
            value |= mask
        mask <<= 1
    return value, pos


def _v96_write_int(bits, value, maximum):
    mask = 1
    while mask < maximum:
        bits.append(1 if (value & mask) else 0)
        mask <<= 1


def _v96_stop_bit_index(bits):
    # UE packets terminate with one stop bit followed by zero byte padding.
    for i in range(len(bits) - 1, -1, -1):
        if bits[i]:
            return i
    raise ValueError("UE3 packet has no stop bit")


def _v96_parse_ue3_packet(plain):
    """Parse AF's UE3 packet/ack/bunch envelope.

    The first live packet validates these exact fields:
      PacketId=0
      Control channel=0, open=1, reliable=1, ChSeq=1, type=1
      NumBits=80
      payload=000190190000721b0000
    """
    bits = _v96_bits_from_bytes(plain)
    stop = _v96_stop_bit_index(bits)
    pos = 0

    packet_id, pos = _v96_read_int(bits, pos, 16384)
    records = []

    while pos < stop:
        is_ack, pos = _v96_read_bits(bits, pos, 1)

        if is_ack:
            ack_id, pos = _v96_read_int(bits, pos, 16384)
            records.append({
                "kind": "ack",
                "ack_packet_id": ack_id,
            })
            continue

        b_control, pos = _v96_read_bits(bits, pos, 1)
        b_open = b_close = 0
        if b_control:
            b_open, pos = _v96_read_bits(bits, pos, 1)
            b_close, pos = _v96_read_bits(bits, pos, 1)

        b_reliable, pos = _v96_read_bits(bits, pos, 1)
        ch_index, pos = _v96_read_int(bits, pos, 1023)

        ch_seq = 0
        if b_reliable:
            ch_seq, pos = _v96_read_int(bits, pos, 1024)

        ch_type = 0
        if b_reliable or b_open:
            ch_type, pos = _v96_read_int(bits, pos, 8)

        # Live packet resolves exactly with MaxPacket=512 bytes.
        num_bits, pos = _v96_read_int(bits, pos, 4096)

        if pos + num_bits > stop:
            raise ValueError(
                f"bunch overrun pos={pos} num_bits={num_bits} stop={stop}"
            )

        payload_bits = bits[pos:pos + num_bits]
        pos += num_bits

        records.append({
            "kind": "bunch",
            "control": b_control,
            "open": b_open,
            "close": b_close,
            "reliable": b_reliable,
            "ch_index": ch_index,
            "ch_seq": ch_seq,
            "ch_type": ch_type,
            "num_bits": num_bits,
            "payload": _v96_bits_to_bytes(payload_bits),
        })

    if pos != stop:
        raise ValueError(
            f"parser ended at bit {pos}; stop bit is {stop}"
        )

    return {
        "packet_id": packet_id,
        "stop_bit": stop,
        "records": records,
    }


def _v96_build_ue3_server_packet(
    server_packet_id,
    ack_packet_id=None,
    control_payload=None,
    control_ch_seq=1,
):
    """Build an ACK and/or reliable server Control-channel bunch."""
    bits = []

    _v96_write_int(
        bits,
        int(server_packet_id) & 0x3FFF,
        16384,
    )

    if ack_packet_id is not None:
        bits.append(1)  # IsAck
        _v96_write_int(
            bits,
            int(ack_packet_id) & 0x3FFF,
            16384,
        )

    if control_payload is not None:
        payload = bytes(control_payload)

        bits.append(0)  # IsAck=0 => bunch

        # The client opened channel 0 in its Hello packet.
        bits.append(0)  # bControl: no open/close flags
        bits.append(1)  # bReliable

        _v96_write_int(bits, 0, 1023)  # Control channel index
        _v96_write_int(
            bits,
            int(control_ch_seq) & 0x3FF,
            1024,
        )
        _v96_write_int(bits, 1, 8)  # CHTYPE_Control
        _v96_write_int(
            bits,
            len(payload) * 8,
            4096,
        )

        for b in payload:
            for bit in range(8):
                bits.append((b >> bit) & 1)

    bits.append(1)  # packet stop bit
    return _v96_bits_to_bytes(bits)


def _v96_fstring_ansi(value):
    """UE3 FString: int32 count including NUL; zero length for empty."""
    if value == "":
        return struct.pack("<i", 0)
    raw = value.encode("ascii") + b"\x00"
    return struct.pack("<i", len(raw)) + raw


def _v96_build_challenge_payload(network_version=0x1B72):
    """Build Assault Fire PH's actual NMT_Challenge(3).

    Reversed from TGame.exe:
      TGame.exe+0xDD8670 first reads a 4-byte integer, then an FString.

    Older v96-v101 omitted that integer. TGame therefore consumed the
    FString length as the integer and then overflowed while reading the
    expected FString, setting the FInBunch error flag and closing channel 0.

    Wire:
      u8  Message = 3
      u32 version/negotiated value (default 0x1B72 / 7026)
      FString Challenge
    """
    ver = int(os.environ.get("AF_DS_CHALLENGE_U32", hex(network_version)), 0)
    challenge = os.environ.get("AF_DS_CHALLENGE_STRING", "00000000")
    return (
        b"\x03"
        + struct.pack("<I", ver & 0xFFFFFFFF)
        + _v96_fstring_ansi(challenge)
    )


def _v97_read_fstring(data, pos):
    """Read the UE3 FString forms seen in AF's control channel."""
    if pos + 4 > len(data):
        raise ValueError("truncated FString length")

    n = struct.unpack_from("<i", data, pos)[0]
    pos += 4

    if n == 0:
        return "", pos

    if n > 0:
        if pos + n > len(data):
            raise ValueError(
                f"truncated ANSI FString n={n} remain={len(data)-pos}"
            )
        raw = data[pos:pos + n]
        pos += n
        if raw.endswith(b"\x00"):
            raw = raw[:-1]
        return raw.decode("latin1", errors="replace"), pos

    chars = -n
    byte_count = chars * 2
    if pos + byte_count > len(data):
        raise ValueError(
            f"truncated UTF16 FString chars={chars} remain={len(data)-pos}"
        )
    raw = data[pos:pos + byte_count]
    pos += byte_count
    if raw.endswith(b"\x00\x00"):
        raw = raw[:-2]
    return raw.decode("utf-16le", errors="replace"), pos


def _v97_parse_control_stream(payload):
    """Parse AF's login-time control stream.

    AF can coalesce multiple NMT messages in one reliable bunch.  The live
    packet begins with NMT_Netspeed(4), int32 10000, then NMT_Login(5).
    """
    payload = bytes(payload)
    pos = 0
    out = []

    while pos < len(payload):
        start = pos
        msg = payload[pos]
        pos += 1

        if msg == 4:
            if pos + 4 > len(payload):
                out.append({
                    "msg": msg,
                    "name": "NMT_Netspeed",
                    "offset": start,
                    "error": "truncated int32",
                })
                break
            rate = struct.unpack_from("<i", payload, pos)[0]
            pos += 4
            out.append({
                "msg": msg,
                "name": "NMT_Netspeed",
                "offset": start,
                "rate": rate,
                "end": pos,
            })
            continue

        if msg == 5:
            try:
                client_response, pos = _v97_read_fstring(payload, pos)
                request_url, pos = _v97_read_fstring(payload, pos)
            except Exception as e:
                out.append({
                    "msg": msg,
                    "name": "NMT_Login",
                    "offset": start,
                    "error": str(e),
                    "tail": payload[pos:].hex(),
                })
                break

            tail = payload[pos:]
            out.append({
                "msg": msg,
                "name": "NMT_Login",
                "offset": start,
                "client_response": client_response,
                "url": request_url,
                "tail": tail,
                "end": len(payload),
            })
            pos = len(payload)
            continue

        out.append({
            "msg": msg,
            "name": {
                0: "NMT_Hello",
                1: "NMT_Welcome",
                3: "NMT_Challenge",
                6: "NMT_Failure",
                9: "NMT_Join",
            }.get(msg, f"NMT_{msg}"),
            "offset": start,
            "tail": payload[pos:],
        })
        break

    return out


def _v98_level_from_login_url(login_url):
    """Extract the already-loaded map token from AF's login URL.

    Live AF login URL is like ":-529/UTFrontEnd?Name=...".
    Returning UTFrontEnd makes the first Welcome acceptance test use a map
    the client is demonstrably already running, isolating protocol framing
    from cooked-map/game-mode problems.
    """
    try:
        base = str(login_url or "").split("?", 1)[0]
        token = base.rsplit("/", 1)[-1].strip()
        return token or "UTFrontEnd"
    except Exception:
        return "UTFrontEnd"


def _v97_build_welcome_payload(level_name=None, game_name=None, redirect_url=None):
    """Build Assault Fire PH's native UE3 NMT_Welcome(1).

    Reversed from this client's UNetPendingLevel::NotifyControlMessage
    (clean TGame image around VA 0x011F5A71): the NMT_Welcome case performs
    exactly TWO FString reads before logging
        "Welcomed by server (Level: %s, Game: %s)".

    So this build's wire schema is:
        u8      NMT_Welcome = 1
        FString LevelName
        FString GameName

    There is NO RedirectURL FString in this old/custom UE3 branch.  v97/v98
    sent a third empty FString (four zero bytes).  ControlChannel then treated
    those leftover bytes as another control message and the client immediately
    closed channel 0.

    redirect_url is intentionally accepted for caller compatibility but is
    NOT serialized.
    """
    if level_name is None:
        level_name = os.environ.get("AF_DS_WELCOME_MAP") or os.environ.get("AF_DS_DEFAULT_MAP", "")
    if game_name is None:
        game_name = os.environ.get("AF_DS_WELCOME_GAME", "")

    return (
        b"\x01"
        + _v96_fstring_ansi(level_name)
        + _v96_fstring_ansi(game_name)
    )


def listen_on_udp_port(port, label="DS-UDP", sock=None):
    """v98: accept AF's coalesced Netspeed+Login and send NMT_Welcome.

    v96 proved ACK + NMT_Challenge are accepted.  The client then sent one
    reliable Control bunch containing BOTH NMT_Netspeed(4) and NMT_Login(5).
    v96 only inspected payload[0], so it missed Login and never sent Welcome.

    v100 parses that stream, logs Login, and replies with Assault Fire's
    native two-FString NMT_Welcome.  The LevelName comes from AF_DS_WELCOME_MAP or AF_DS_DEFAULT_MAP; no PvE map is hard-coded.
    """
    s = sock
    if s is None:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", port))

    log(
        label,
        f"Listening on UDP port {port}; "
        f"v104 UE3 ACK+Challenge+Welcome+post-Join keepalive enabled "
        f"DSKey={TGAME_DS_KEY.hex()}"
    )

    peer_state = {}

    while True:
        try:
            data, addr = s.recvfrom(65535)

            st = peer_state.setdefault(addr, {
                "rx_count": 0,
                "server_packet_id": 0,
                "server_control_seq": 1,
                "challenge_sent": False,
                "welcome_sent": False,
                "welcome_packet_id": None,
                "acked_packets": set(),
                "join_seen": False,
                "last_server_send": 0.0,
                "last_keepalive": 0.0,
            })
            st["rx_count"] += 1
            n = st["rx_count"]

            try:
                plain, _ = _v96_ds_udp_decrypt(data)
                pkt = _v96_parse_ue3_packet(plain)
            except Exception as e:
                log(
                    label,
                    f"v100 decode ERROR #{n} from {addr}: "
                    f"{type(e).__name__}: {e}; "
                    f"wire={data.hex()}"
                )
                continue

            bunches = [
                r for r in pkt["records"]
                if r["kind"] == "bunch"
            ]
            ack_records = [
                r for r in pkt["records"]
                if r["kind"] == "ack"
            ]

            reliable_seen = False
            hello_seen = False
            login_seen = False
            login_info = None
            descriptions = []

            for b in bunches:
                payload = b["payload"]
                msg = None

                if (
                    b["ch_index"] == 0
                    and b["num_bits"] >= 8
                    and payload
                ):
                    msg = payload[0]

                if b["reliable"]:
                    reliable_seen = True

                if msg == 0:
                    hello_seen = True

                parsed_control = []
                if b["ch_index"] == 0 and payload:
                    parsed_control = _v97_parse_control_stream(payload)
                    for cm in parsed_control:
                        if cm.get("msg") == 5 and "error" not in cm:
                            login_seen = True
                            login_info = cm
                        if cm.get("msg") == 9 and "error" not in cm:
                            st["join_seen"] = True

                cm_desc = ""
                if parsed_control:
                    cm_desc = " controls=[" + ", ".join(
                        cm.get("name", "?")
                        + (
                            f"(rate={cm.get('rate')})"
                            if cm.get("msg") == 4 and "rate" in cm
                            else ""
                        )
                        for cm in parsed_control
                    ) + "]"

                descriptions.append(
                    f"ch={b['ch_index']} type={b['ch_type']} "
                    f"ctl={b['control']} open={b['open']} close={b['close']} rel={b['reliable']} "
                    f"seq={b['ch_seq']} bits={b['num_bits']} "
                    f"msg={('0x%02x' % msg) if msg is not None else '-'} "
                    f"payload={payload.hex()}"
                    + cm_desc
                )

            log(
                label,
                f"v100 RX #{n} {addr} "
                f"clear={len(plain)}B packet_id={pkt['packet_id']} "
                f"ack_records="
                f"{[a['ack_packet_id'] for a in ack_records]} "
                + (
                    " | ".join(descriptions)
                    if descriptions
                    else "(no bunches)"
                )
            )

            # v100 diagnostics: a zero-bit Control-channel CloseBunch is the
            # clearest signal that TGame rejected the Welcome / travel setup.
            for b in bunches:
                if b.get("ch_index") == 0 and b.get("control") and b.get("close"):
                    log(
                        label,
                        "v100 CLIENT CONTROL CHANNEL CLOSE: "
                        f"packet_id={pkt['packet_id']} seq={b.get('ch_seq')} "
                        f"bits={b.get('num_bits')}"
                    )

            acked_now = [a["ack_packet_id"] for a in ack_records]
            if st.get("welcome_packet_id") is not None and st["welcome_packet_id"] in acked_now:
                log(
                    label,
                    f"v100 WELCOME PACKET ACKED by client: "
                    f"server_packet_id={st['welcome_packet_id']}"
                )

            control_payload = None
            control_name = "-"

            if hello_seen and not st["challenge_sent"]:
                control_payload = _v96_build_challenge_payload()
                control_name = "NMT_Challenge(3)"
                st["challenge_sent"] = True
                log(
                    label,
                    "v100 NMT_Hello(0) accepted -> "
                    "ACK + NMT_Challenge(3, '00000000')"
                )

            elif login_seen and not st["welcome_sent"]:
                # v100: v99 proved the exact 2-FString Welcome still reaches
                # an immediate client CloseBunch when LevelName=UTFrontEnd.
                # The NMT_Welcome handler in this TGame sets
                # bSuccessfullyConnected=TRUE after the two FString reads;
                # map travel happens immediately afterwards.  Probe the
                # cooked Survival main package instead of asking the client
                # to travel back to its lobby/frontend package.
                #
                # Use the selected/configured PvE map rather than a fixed map.
                level_name = (
                    os.environ.get("AF_DS_WELCOME_MAP")
                    or os.environ.get("AF_DS_DEFAULT_MAP", "")
                )
                game_name = os.environ.get("AF_DS_WELCOME_GAME", "")
                redirect_url = None  # v100: AF TGame NMT_Welcome has no RedirectURL field
                control_payload = _v97_build_welcome_payload(
                    level_name,
                    game_name,
                    redirect_url,
                )
                control_name = "NMT_Welcome(1)"
                st["welcome_sent"] = True

                if login_info is not None:
                    log(
                        label,
                        "v100 LOGIN DECODED: "
                        f"ClientResponse={login_info.get('client_response')!r} "
                        f"URL={login_info.get('url')!r} "
                        f"tail={login_info.get('tail', b'').hex()}"
                    )

                log(
                    label,
                    "v100 NMT_Login(5) accepted -> "
                    f"ACK + NMT_Welcome(1) "
                    f"Level={level_name!r} Game={game_name!r} "
                    "Redirect=OMITTED (AF native 2-FString schema)"
                )
                log(
                    label,
                    "v100 MAP-TRAVEL PROBE: "
                    "room mode=0x00002001 map=0x002F ; "
                    f"Welcome LevelName={level_name!r}. "
                    "Expected success signal: Welcome ACK / NMT_Netspeed / "
                    "NMT_Join instead of immediate CloseBunch."
                )

            # Reliable bunches must be ACKed by packet ID.  This is the exact
            # missing behavior responsible for v95's one-second Hello retry.
            need_ack = (
                reliable_seen
                and pkt["packet_id"] not in st["acked_packets"]
            )

            if need_ack or control_payload is not None:
                out_plain = _v96_build_ue3_server_packet(
                    server_packet_id=st["server_packet_id"],
                    ack_packet_id=(
                        pkt["packet_id"]
                        if need_ack
                        else None
                    ),
                    control_payload=control_payload,
                    control_ch_seq=st["server_control_seq"],
                )
                out_wire = _v96_ds_udp_encrypt(out_plain)
                s.sendto(out_wire, addr)
                st["last_server_send"] = time.monotonic()

                if control_name == "NMT_Welcome(1)":
                    st["welcome_packet_id"] = st["server_packet_id"]

                log(
                    label,
                    f"v100 TX packet_id={st['server_packet_id']} "
                    f"ack="
                    f"{pkt['packet_id'] if need_ack else '-'} "
                    f"control={control_name} "
                    f"plain={out_plain.hex()} "
                    f"wire={out_wire.hex()}"
                )

                st["server_packet_id"] = (
                    st["server_packet_id"] + 1
                ) & 0x3FFF

                if need_ack:
                    st["acked_packets"].add(pkt["packet_id"])

                if control_payload is not None:
                    st["server_control_seq"] = (
                        st["server_control_seq"] + 1
                    ) & 0x3FF

            if login_seen:
                log(
                    label,
                    "v100 MILESTONE: coalesced NMT_Login(5) received and AF-native "
                    "2-FString NMT_Welcome(1) sent. If schema is correct, the "
                    "next client control message should be NMT_Netspeed(4), not CloseBunch."
                )

            # v104 diagnostic: once NMT_Join has been received and ACKed, the
            # old probe becomes completely silent server->client.  The live
            # trace shows the client then sends empty packets for ~60 seconds
            # and closes control channel 0.  Send a valid empty UE3 packet
            # once per second so LastReceiveTime stays fresh while we reverse
            # the real post-Join actor-channel replication.
            if st.get("join_seen"):
                now = time.monotonic()
                if now - float(st.get("last_keepalive", 0.0)) >= 1.0:
                    ka_plain = _v96_build_ue3_server_packet(
                        server_packet_id=st["server_packet_id"],
                        ack_packet_id=None,
                        control_payload=None,
                        control_ch_seq=st["server_control_seq"],
                    )
                    ka_wire = _v96_ds_udp_encrypt(ka_plain)
                    s.sendto(ka_wire, addr)
                    log(
                        label,
                        f"v104 POST-JOIN KEEPALIVE packet_id={st['server_packet_id']} "
                        f"plain={ka_plain.hex()} wire={ka_wire.hex()}"
                    )
                    st["server_packet_id"] = (
                        st["server_packet_id"] + 1
                    ) & 0x3FFF
                    st["last_server_send"] = now
                    st["last_keepalive"] = now

        except Exception as e:
            log(
                label,
                f"UDP receive error: {type(e).__name__}: {e}"
            )


# ---------------------------------------------------------------------------
# Listener
# ---------------------------------------------------------------------------

def _bind_tcp_listener(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", int(port)))
    s.listen(10)
    return s


def _bind_udp_listener(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", int(port)))
    return s


def _prepare_listener_sockets():
    specs = [
        ("VERSION", "tcp", 9060),
        ("AUTH", "tcp", 8000),
        ("DIR", "tcp", 9010),
        ("ROLE", "tcp", 65005),
        ("ZONE", "tcp", TGAME_ZONE_PORT),
        ("DS-TCP", "tcp", TGAME_DS_PORT),
        ("DS-UDP", "udp", TGAME_DS_PORT),
    ]
    bound = []
    try:
        for label, kind, port in specs:
            sock = (
                _bind_tcp_listener(port)
                if kind == "tcp"
                else _bind_udp_listener(port)
            )
            bound.append((label, kind, port, sock))
            log("MAIN", f"prebound {label} {kind.upper()} 0.0.0.0:{port}")
        return bound
    except Exception:
        for _label, _kind, _port, sock in bound:
            try:
                sock.close()
            except Exception:
                pass
        raise


def listen_on_port(port, label, sock=None):
    s = sock if sock is not None else _bind_tcp_listener(port)

    log(
        label,
        f"Listening on port {port}"
    )

    while True:
        try:
            conn, addr = s.accept()

            if label == "VERSION":
                target = handle_version
                args = (conn, addr)

            elif label == "AUTH":
                target = handle_auth
                args = (conn, addr)

            elif label == "DIR":
                target = handle_dir
                args = (conn, addr)

            else:
                target = handle_placeholder
                args = (conn, addr, label)

            threading.Thread(
                target=target,
                args=args,
                daemon=True
            ).start()

        except Exception as e:
            log(
                label,
                f"accept error: {e}"
            )


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

print("[BOOT] BUILD=v143b-GITHUB-MAIN-c7ad3-BAG-CATALOG-DYNAMIC-1-5-A006-RECONCILE-v156+SQLITE-EXP-A005 + STABLE LOGIN UIN + SQLITE PROFILE/WALLET/INVENTORY + F301/F302 + RESTART-RESUME-HOSTED-MULTISESSION-v1 + A00A-UPDPROP-v100 + NO-AP-MEMSYNC")
print(
    f"[BOOT] Hosted reconnect persistence: sqlite-multisession=enabled "
    f"session_ttl={SESSION_TTL_SECONDS}s "
    f"touch_interval={TGAME_SESSION_TOUCH_INTERVAL_SECONDS:.0f}s "
    f"binding=UIN+client-IP+encrypted-transport-key",
    flush=True,
)
print(
    "[BOOT] First-login nickname v26g: VERIFIED same-session A003 -> "
    "defer A006 -> A146/A147 -> A005 -> A006; "
    "atomic nickname claim + idempotent A002; verified-v25 season compatibility"
)
print("[BOOT] First-login CreateRole gate: nickname=NULL -> stock CreateRole path; profile props are deferred until post-A147")
print(f"[BOOT] r13 identity projection self-test={'PASS' if _R13_IDENTITY_PROJECTION_SELFTEST else 'FAIL'}")
print(f"[BOOT] r14 A102 enterability projection self-test={'PASS' if _R14_A102_PROJECTION_SELFTEST else 'FAIL'}")
print(f"[BOOT] r15 live A103 EnterRoomByRoomId self-test={'PASS' if _R15_A103_ENTER_SELFTEST else 'FAIL'}")
print(f"[BOOT] r17 A102 FIRST|LAST self-test={'PASS' if _R17_A102_PREFIX_SELFTEST else 'FAIL'} pageflags=0x{R17_A102_PAGEFLAGS_SINGLE:04x}")
print(
    f"[BOOT] r20 With32 seat mapping self-test="
    f"{'PASS' if _R20_SPARSE_SEAT_MAPPING_SELFTEST else 'FAIL'} "
    "mode-agnostic even-capacity=2..16 left=0..7 right=16..23"
)
print(
    "[BOOT] No Late Join: VERIFIED stock PH semantics "
    f"allow-late bit=0x{TGAME_LATE_JOIN_ALLOWED_FLAG:08X}; "
    f"self-test={'PASS' if _V56_NO_LATE_JOIN_FLAG_SELFTEST else 'FAIL'}; "
    "bit SET=late join allowed, bit CLEAR=No Late Join"
)
_v139_protocol_boot_report()
print("[BOOT] Default character: Sofia item=100600 + components 300121/300122/100602; primary=QBS09 item=100497 role_gid=0x%016X" % V109_ROLE_GID)
_v4_db_counts = PLAYER_DB.counts()
print(
    "[BOOT] Mall SQLite v4: "
    f"commodities={len(V140_SHOP_ITEM_MAP)} "
    f"bundles={len(V140_COMMODITY_BUNDLES)} "
    f"db={PLAYER_DB.db_path} "
    f"identities={_v4_db_counts['game_identities']} "
    f"profiles={_v4_db_counts['player_profiles']} "
    f"inventory_rows={_v4_db_counts['player_inventory']} "
    f"legacy_json={V140_MALL_STATE_PATH} "
    f"legacy_exists={V140_MALL_STATE_PATH.exists()}"
)
print(
    "[BOOT] AP synchronization: native A50E -> A00A UpdatePlayerProperty"
)
print(
    f"[BOOT] Runtime mode: {RUNTIME_MODE}; "
    f"development website={'enabled' if DEV_WEB_ENABLED else 'disabled'}"
)
if RUNTIME_MODE == "production":
    print(
        "[BOOT] Production safety: registration/login/admin website will NOT start.",
        flush=True,
    )
print(
    f"[BOOT] Stable-v143b DS spawner: enabled={V143B_DS_CONFIG.enabled} "
    f"max_instances={V143B_DS_CONFIG.max_instances} "
    f"public={V143B_DS_CONFIG.public_host}:{V143B_DS_CONFIG.public_port_base}+slot "
    f"afdev={V143B_DS_CONFIG.target_host}:{V143B_DS_CONFIG.target_port_base}+slot "
    f"game_dir={V143B_DS_CONFIG.game_dir!r} "
    f"game_dir_source={V143B_DS_CONFIG.game_dir_source} "
    f"default_map={V143B_DS_CONFIG.default_map!r} "
    "flow=A10A reserve only; A3A0/A113 arm bridge + A11A; first DS UDP -> spawn v48; v72 zero-rekey BEFORE SESSION_READY; latch first handshake until AFDEV replies"
)
print(
    f"[BOOT] Stable-v143b spawner scripts: loader={V143B_DS_CONFIG.loader_script} "
    f"bridge={V143B_DS_CONFIG.bridge_script} runtime={V143B_DS_CONFIG.runtime_dir}"
)

if __name__ == "__main__":
    if SERVER_ONLY_MODE:
        if RSA_PRIV is None:
            print(
                "[SERVER-ONLY] FAILED - a valid RSA PRIVATE.PEM is still required "
                "for AUTH. Use --private-key <path> or AF_PRIVATE_KEY.",
                flush=True,
            )
            raise SystemExit(2)

        # Never let a stale successful client preflight unlock local launch
        # helpers while this process is intentionally running without client
        # validation.
        _server_only_status = default_preflight_status_path()
        if _server_only_status.exists():
            update_launch_gate_status(
                ready=False,
                reason="server-only mode: local launch gate intentionally locked",
            )

        print(
            "[SERVER-ONLY] ENABLED - skipping local client/TCLS/APClient/hosts "
            "preflight. Backend listeners may start; local game launch helpers "
            "remain LOCKED.",
            flush=True,
        )
        print(
            f"[SERVER-ONLY] RSA private key: {PRIVATE_KEY_PATH}",
            flush=True,
        )
    elif not run_server_preflight(Path(PRIVATE_KEY_PATH)):
        raise SystemExit(2)

    # Always show this one line even when the selected console threshold is
    # WARNING/ERROR so users know where the full development trace is going.
    print(
        "[LOGGING] "
        f"console={_SERVER_LOGGER.console_level_name} "
        f"file=DEBUG+ path={_SERVER_LOGGER.path}",
        flush=True,
    )
    log(
        "BOOT",
        f"logging initialized console={_SERVER_LOGGER.console_level_name} "
        f"file=DEBUG+ path={_SERVER_LOGGER.path}",
        level="DEBUG",
    )

    _development_web = None
    try:
        _development_web = DevelopmentWebProcess(
            repo_root=Path(__file__).resolve().parents[1],
            db_path=PLAYER_DB.db_path,
            argv=sys.argv[1:],
            env=os.environ,
        )
        _development_web.start()
    except DevelopmentWebError as web_exc:
        print(
            f"[WEB] DEVELOPMENT STARTUP WARNING: {web_exc}",
            flush=True,
        )
        print(
            "[WEB] Backend startup will continue. Registration website "
            "is unavailable until the port/app problem is fixed.",
            flush=True,
        )
        log(
            "WEB",
            f"development website startup warning: "
            f"{type(web_exc).__name__}: {web_exc}",
        )

    # Mutable DS runtime state is created only after preflight succeeds.
    _v143b_init_spawner()

    print(
        f"[BOOT] VERSION response: "
        f"{len(VERSION_RESPONSE)}B",
        flush=True
    )

    print(
        f"[BOOT] DH prime: "
        f"{PRIME_BYTES.hex()}",
        flush=True
    )

    print(
        f"[BOOT] IV: "
        f"{IV.hex()}",
        flush=True
    )

    try:
        listener_sockets = _prepare_listener_sockets()
    except Exception as bind_exc:
        reason = f"listener bind failed: {type(bind_exc).__name__}: {bind_exc}"
        log("MAIN", reason)
        if _development_web is not None:
            _development_web.stop()
        if not SERVER_ONLY_MODE:
            update_launch_gate_status(ready=False, reason=reason)
        raise SystemExit(3)

    # Normal local-client mode keeps the strict launch gate. Server-only mode
    # deliberately starts listeners without ever unlocking local launch helpers.
    if SERVER_ONLY_MODE:
        print(
            "[SERVER-ONLY] All required listeners bound; local game launch "
            "gate remains LOCKED.",
            flush=True,
        )
    elif not update_launch_gate_status(ready=True):
        for _label, _kind, _port, sock in listener_sockets:
            try:
                sock.close()
            except Exception:
                pass
        if _development_web is not None:
            _development_web.stop()
        raise SystemExit(4)

    # Recover waiting-room membership only for unexpired transport sessions.
    # Active matches depend on process-local UE3 servers and cannot survive a
    # backend restart, so RoomRegistry drops those while preserving lobby rooms.
    try:
        restart_room_state = V150_ROOM_REGISTRY.recover_after_restart(
            retain_uins=get_unexpired_session_uins(db_path=PLAYER_DB.db_path),
        )
    except Exception as lobby_db_exc:
        reason = (
            "lobby database initialization failed: "
            f"{type(lobby_db_exc).__name__}: {lobby_db_exc}"
        )
        log("ROOM", reason)
        for _label, _kind, _port, sock in listener_sockets:
            try:
                sock.close()
            except Exception:
                pass
        if _development_web is not None:
            try:
                _development_web.stop()
            except Exception:
                pass
        if not SERVER_ONLY_MODE:
            update_launch_gate_status(ready=False, reason=reason)
        raise SystemExit(5)
    log(
        "ROOM",
        f"SQLite lobby state ready db={V150_ROOM_REGISTRY.db_path}; "
        f"recovered waiting rooms={restart_room_state['recovered_rooms']} "
        f"removed rooms={restart_room_state['removed_rooms']} "
        f"expired members={restart_room_state['removed_members']}",
    )

    for label, kind, port, sock in listener_sockets:
        target = listen_on_port if kind == "tcp" else listen_on_udp_port
        threading.Thread(
            target=target,
            args=(port, label, sock),
            daemon=True,
        ).start()

    print(
        "[MAIN] All listeners running.",
        flush=True
    )

    try:
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print(
            "\n[MAIN] Shutting down.",
            flush=True
        )
    finally:
        SERVER_SHUTTING_DOWN.set()
        if _development_web is not None:
            try:
                _development_web.stop()
            except Exception as web_stop_exc:
                print(
                    f"[WEB] shutdown warning: "
                    f"{type(web_stop_exc).__name__}: {web_stop_exc}",
                    flush=True,
                )
        if not SERVER_ONLY_MODE:
            update_launch_gate_status(
                ready=False,
                reason="server shutting down",
            )
