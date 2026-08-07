#pragma once

// Version, in one place. The resource compiler substitutes these into
// VERSIONINFO and the application reads the same strings for its title bar and
// its stats output, so a release cannot end up labelled two different things.
#define APP_NAME            "PCAP Replay"
#define APP_VERSION_STR     "1.2"
#define APP_VERSION_FULL    "1.2.0.0"
#define APP_VERSION_COMMA   1,2,0,0

#define IDD_REPLAY          101
#define IDI_APP             102

// ---- source ---------------------------------------------------------------
#define IDC_RED             1001
#define IDC_RED_BROWSE      1002
#define IDC_BLUE            1003
#define IDC_BLUE_BROWSE     1004
#define IDC_FILEINFO        1005
#define IDC_RING            1006
#define IDC_SKIP            1007

// ---- transmit -------------------------------------------------------------
#define IDC_MODE_6          1010
#define IDC_MODE_7          1011
#define IDC_A_GROUP         1012
#define IDC_A_PORT          1013
#define IDC_A_IFACE         1014
#define IDC_B_GROUP         1015
#define IDC_B_PORT          1016
#define IDC_B_IFACE         1017
#define IDC_TTL             1018
#define IDC_LOOPBACK        1019
#define IDC_TIMECODE        1020
#define IDC_DURATION        1021

// ---- faults ---------------------------------------------------------------
#define IDC_F_LOSS_A        1030
#define IDC_F_LOSS_B        1031
#define IDC_F_BURST         1032
#define IDC_F_REORDER       1033
#define IDC_F_DUP           1034
#define IDC_F_SEQJUMP       1035
#define IDC_F_RATE          1036

// ---- NMOS -----------------------------------------------------------------
#define IDC_NMOS_EN         1040
#define IDC_NMOS_LABEL      1041
#define IDC_NMOS_PORT       1042
#define IDC_NMOS_IFACE      1043
#define IDC_NMOS_MDNS       1044
#define IDC_NMOS_MANUAL     1045
#define IDC_NMOS_HOST       1046
#define IDC_NMOS_RPORT      1047
#define IDC_NMOS_P2P        1048
#define IDC_NMOS_STATUS     1049

// ---- run / status ---------------------------------------------------------
#define IDC_START           1060
#define IDC_SUMMARY         1061
#define IDC_STATSURL        1062
#define IDC_STATUS          1063
