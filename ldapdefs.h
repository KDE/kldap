/*
  This file is part of libkldap.
  Copyright (c) 2004-2006 Szombathelyi György <gyurco@freemail.hu>

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Library General  Public
  License as published by the Free Software Foundation; either
  version 2 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Library General Public License for more details.

  You should have received a copy of the GNU Library General Public License
  along with this library; see the file COPYING.LIB.  If not, write to
  the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
  Boston, MA 02110-1301, USA.
*/

#ifndef KLDAP_DEFS_H
#define KLDAP_DEFS_H

/**
 * LDAP Error codes.
 * These codes taken from openldap's ldap.h, and prefixed with KLDAP_
 * instead of LDAP_, just for applications which uses the kldap library
 * doesn't need to include openldap headers
 */

#define KLDAP_SUCCESS                    0x00

#define KLDAP_RANGE(n,x,y)       (((x) <= (n)) && ((n) <= (y)))

#define KLDAP_OPERATIONS_ERROR           0x01
#define KLDAP_PROTOCOL_ERROR             0x02
#define KLDAP_TIMELIMIT_EXCEEDED         0x03
#define KLDAP_SIZELIMIT_EXCEEDED         0x04
#define KLDAP_COMPARE_FALSE              0x05
#define KLDAP_COMPARE_TRUE               0x06
#define KLDAP_AUTH_METHOD_NOT_SUPPORTED  0x07
#define KLDAP_STRONG_AUTH_NOT_SUPPORTED  KLDAP_AUTH_METHOD_NOT_SUPPORTED
#define KLDAP_STRONG_AUTH_REQUIRED       0x08
#define KLDAP_STRONGER_AUTH_REQUIRED     KLDAP_STRONG_AUTH_REQUIRED
#define KLDAP_PARTIAL_RESULTS            0x09    /* LDAPv2+ (not LDAPv3) */

#define KLDAP_REFERRAL                   0x0a /* LDAPv3 */
#define KLDAP_ADMINLIMIT_EXCEEDED        0x0b /* LDAPv3 */
#define KLDAP_UNAVAILABLE_CRITICAL_EXTENSION     0x0c /* LDAPv3 */
#define KLDAP_CONFIDENTIALITY_REQUIRED   0x0d /* LDAPv3 */
#define KLDAP_SASL_BIND_IN_PROGRESS      0x0e /* LDAPv3 */

#define KLDAP_ATTR_ERROR(n)      KLDAP_RANGE((n),0x10,0x15) /* 16-21 */

#define KLDAP_NO_SUCH_ATTRIBUTE          0x10
#define KLDAP_UNDEFINED_TYPE             0x11
#define KLDAP_INAPPROPRIATE_MATCHING     0x12
#define KLDAP_CONSTRAINT_VIOLATION       0x13
#define KLDAP_TYPE_OR_VALUE_EXISTS       0x14
#define KLDAP_INVALID_SYNTAX             0x15

#define KLDAP_NAME_ERROR(n)      KLDAP_RANGE((n),0x20,0x24) /* 32-34,36 */

#define KLDAP_NO_SUCH_OBJECT             0x20
#define KLDAP_ALIAS_PROBLEM              0x21
#define KLDAP_INVALID_DN_SYNTAX          0x22
#define KLDAP_IS_LEAF                    0x23 /* not LDAPv3 */
#define KLDAP_ALIAS_DEREF_PROBLEM        0x24

#define KLDAP_SECURITY_ERROR(n)  KLDAP_RANGE((n),0x2F,0x32) /* 47-50 */

#define KLDAP_PROXY_AUTHZ_FAILURE        0x2F /* LDAPv3 proxy authorization */
#define KLDAP_INAPPROPRIATE_AUTH         0x30
#define KLDAP_INVALID_CREDENTIALS        0x31
#define KLDAP_INSUFFICIENT_ACCESS        0x32

#define KLDAP_SERVICE_ERROR(n)   KLDAP_RANGE((n),0x33,0x36) /* 51-54 */

#define KLDAP_BUSY                       0x33
#define KLDAP_UNAVAILABLE                0x34
#define KLDAP_UNWILLING_TO_PERFORM       0x35
#define KLDAP_LOOP_DETECT                0x36

#define KLDAP_UPDATE_ERROR(n)    KLDAP_RANGE((n),0x40,0x47) /* 64-69,71 */

#define KLDAP_NAMING_VIOLATION           0x40
#define KLDAP_OBJECT_CLASS_VIOLATION     0x41
#define KLDAP_NOT_ALLOWED_ON_NONLEAF     0x42
#define KLDAP_NOT_ALLOWED_ON_RDN         0x43
#define KLDAP_ALREADY_EXISTS             0x44
#define KLDAP_NO_OBJECT_CLASS_MODS       0x45
#define KLDAP_RESULTS_TOO_LARGE          0x46 /* CLDAP */
#define KLDAP_AFFECTS_MULTIPLE_DSAS      0x47

#define KLDAP_OTHER                      0x50

/* LCUP operation codes (113-117) - not implemented */
#define KLDAP_CUP_RESOURCES_EXHAUSTED    0x71
#define KLDAP_CUP_SECURITY_VIOLATION     0x72
#define KLDAP_CUP_INVALID_DATA           0x73
#define KLDAP_CUP_UNSUPPORTED_SCHEME     0x74
#define KLDAP_CUP_RELOAD_REQUIRED        0x75

/* Cancel operation codes (118-121) */
#define KLDAP_CANCELLED                  0x76
#define KLDAP_NO_SUCH_OPERATION          0x77
#define KLDAP_TOO_LATE                   0x78

#define KLDAP_CANNOT_CANCEL              0x79

/* Assertion control (122) */
#define KLDAP_ASSERTION_FAILED           0x7A

/* Experimental result codes */
#define KLDAP_E_ERROR(n) KLDAP_RANGE((n),0x1000,0x3FFF)

/* LDAP Sync (4096) */
#define KLDAP_SYNC_REFRESH_REQUIRED      0x1000

/* Private Use result codes */
#define KLDAP_X_ERROR(n) KLDAP_RANGE((n),0x4000,0xFFFF)

#define KLDAP_X_SYNC_REFRESH_REQUIRED    0x4100 /* defunct */
#define KLDAP_X_ASSERTION_FAILED         0x410f /* defunct */

/* for the LDAP No-Op control */
#define KLDAP_X_NO_OPERATION             0x410e

/** API Error Codes
 *
 * Based on draft-ietf-ldap-c-api-xx
 * but with new negative code values
 */
#define KLDAP_API_ERROR(n)               ((n)<0)
#define KLDAP_API_RESULT(n)              ((n)<=0)

#define KLDAP_SERVER_DOWN                (-1)
#define KLDAP_LOCAL_ERROR                (-2)
#define KLDAP_ENCODING_ERROR             (-3)
#define KLDAP_DECODING_ERROR             (-4)
#define KLDAP_TIMEOUT                    (-5)
#define KLDAP_AUTH_UNKNOWN               (-6)
#define KLDAP_FILTER_ERROR               (-7)
#define KLDAP_USER_CANCELLED             (-8)
#define KLDAP_PARAM_ERROR                (-9)
#define KLDAP_NO_MEMORY                  (-10)
#define KLDAP_CONNECT_ERROR              (-11)
#define KLDAP_NOT_SUPPORTED              (-12)
#define KLDAP_CONTROL_NOT_FOUND          (-13)
#define KLDAP_NO_RESULTS_RETURNED        (-14)
#define KLDAP_MORE_RESULTS_TO_RETURN     (-15)   /* Obsolete */
#define KLDAP_CLIENT_LOOP                (-16)
#define KLDAP_REFERRAL_LIMIT_EXCEEDED    (-17)

/*
 * KLDAP Specific
 */

#define KLDAP_SASL_ERROR	-0xff

#endif //KLDAP_DEFS_H
