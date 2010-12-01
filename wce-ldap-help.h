/*
 * winceldap - LDAP helper functions for Windows CE
 * Copyright 2010 Andre Heinecke
 *
 * Derived from:
 *
 * WLDAP32 - LDAP support for Wine
 *
 * Copyright 2005 Hans Leidekker
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */
#ifndef WCE_LDAP_HELP_H
#define WCE_LDAP_HELP_H
ULONG map_error( int );

/* A set of helper functions to convert LDAP data structures
 * to and from ansi (A), wide character (W) and utf8 (U) encodings.
 */

static inline char *strdupU( const char *src )
{
    char *dst;

    if (!src) return NULL;
    dst = ( char * )HeapAlloc( GetProcessHeap(), 0, (strlen( src ) + 1) * sizeof(char) );
    if (dst)
        strcpy( dst, src );
    return dst;
}

static inline LPWSTR strAtoW( LPCSTR str )
{
    LPWSTR ret = NULL;
    if (str)
    {
        DWORD len = MultiByteToWideChar( CP_ACP, 0, str, -1, NULL, 0 );
        if ((ret = ( WCHAR* )HeapAlloc( GetProcessHeap(), 0, len * sizeof(WCHAR) )))
            MultiByteToWideChar( CP_ACP, 0, str, -1, ret, len );
    }
    return ret;
}

static inline LPSTR strWtoA( LPCWSTR str )
{
    LPSTR ret = NULL;
    if (str)
    {
        DWORD len = WideCharToMultiByte( CP_ACP, 0, str, -1, NULL, 0, NULL, NULL );
        if ((ret = ( char* )HeapAlloc( GetProcessHeap(), 0, len )))
            WideCharToMultiByte( CP_ACP, 0, str, -1, ret, len, NULL, NULL );
    }
    return ret;
}

static inline char *strWtoU( LPCWSTR str )
{
    LPSTR ret = NULL;
    if (str)
    {
        DWORD len = WideCharToMultiByte( CP_UTF8, 0, str, -1, NULL, 0, NULL, NULL );
        if ((ret = ( char * )HeapAlloc( GetProcessHeap(), 0, len )))
            WideCharToMultiByte( CP_UTF8, 0, str, -1, ret, len, NULL, NULL );
    }
    return ret;
}

static inline LPWSTR strUtoW( char *str )
{
    LPWSTR ret = NULL;
    if (str)
    {
        DWORD len = MultiByteToWideChar( CP_UTF8, 0, str, -1, NULL, 0 );
        if ((ret = ( WCHAR* )HeapAlloc( GetProcessHeap(), 0, len * sizeof(WCHAR) )))
            MultiByteToWideChar( CP_UTF8, 0, str, -1, ret, len );
    }
    return ret;
}

static inline void strfreeA( LPSTR str )
{
    HeapFree( GetProcessHeap(), 0, str );
}

static inline void strfreeW( LPWSTR str )
{
    HeapFree( GetProcessHeap(), 0, str );
}

static inline void strfreeU( char *str )
{
    HeapFree( GetProcessHeap(), 0, str );
}

static inline DWORD strarraylenA( LPSTR *strarray )
{
    LPSTR *p = strarray;
    while (*p) p++;
    return p - strarray;
}

static inline DWORD strarraylenW( LPWSTR *strarray )
{
    LPWSTR *p = strarray;
    while (*p) p++;
    return p - strarray;
}

static inline DWORD strarraylenU( char **strarray )
{
    char **p = strarray;
    while (*p) p++;
    return p - strarray;
}

static inline LPWSTR *strarrayAtoW( LPSTR *strarray )
{
    LPWSTR *strarrayW = NULL;
    DWORD size;

    if (strarray)
    {
        size  = sizeof(WCHAR*) * (strarraylenA( strarray ) + 1);
        strarrayW = ( WCHAR** )HeapAlloc( GetProcessHeap(), 0, size );

        if (strarrayW)
        {
            LPSTR *p = strarray;
            LPWSTR *q = strarrayW;

            while (*p) *q++ = strAtoW( *p++ );
            *q = NULL;
        }
    }
    return strarrayW;
}

static inline LPSTR *strarrayWtoA( LPWSTR *strarray )
{
    LPSTR *strarrayA = NULL;
    DWORD size;

    if (strarray)
    {
        size = sizeof(LPSTR) * (strarraylenW( strarray ) + 1);
        strarrayA = ( char** )HeapAlloc( GetProcessHeap(), 0, size );

        if (strarrayA)
        {
            LPWSTR *p = strarray;
            LPSTR *q = strarrayA;

            while (*p) *q++ = strWtoA( *p++ );
            *q = NULL;
        }
    }
    return strarrayA;
}

static inline char **strarrayWtoU( LPWSTR *strarray )
{
    char **strarrayU = NULL;
    DWORD size;

    if (strarray)
    {
        size = sizeof(char*) * (strarraylenW( strarray ) + 1);
        strarrayU = ( char** )HeapAlloc( GetProcessHeap(), 0, size );

        if (strarrayU)
        {
            LPWSTR *p = strarray;
            char **q = strarrayU;

            while (*p) *q++ = strWtoU( *p++ );
            *q = NULL;
        }
    }
    return strarrayU;
}

static inline LPWSTR *strarrayUtoW( char **strarray )
{
    LPWSTR *strarrayW = NULL;
    DWORD size;

    if (strarray)
    {
        size = sizeof(WCHAR*) * (strarraylenU( strarray ) + 1);
        strarrayW = ( WCHAR ** )HeapAlloc( GetProcessHeap(), 0, size );

        if (strarrayW)
        {
            char **p = strarray;
            LPWSTR *q = strarrayW;

            while (*p) *q++ = strUtoW( *p++ );
            *q = NULL;
        }
    }
    return strarrayW;
}

static inline void strarrayfreeA( LPSTR *strarray )
{
    if (strarray)
    {
        LPSTR *p = strarray;
        while (*p) strfreeA( *p++ );
        HeapFree( GetProcessHeap(), 0, strarray );
    }
}

static inline void strarrayfreeW( LPWSTR *strarray )
{
    if (strarray)
    {
        LPWSTR *p = strarray;
        while (*p) strfreeW( *p++ );
        HeapFree( GetProcessHeap(), 0, strarray );
    }
}

static inline void strarrayfreeU( char **strarray )
{
    if (strarray)
    {
        char **p = strarray;
        while (*p) strfreeU( *p++ );
        HeapFree( GetProcessHeap(), 0, strarray );
    }
}

static inline struct berval *bvdup( struct berval *bv )
{
    struct berval *berval;
    DWORD size = sizeof(struct berval) + bv->bv_len;

    berval = ( struct berval * )HeapAlloc( GetProcessHeap(), 0, size );
    if (berval)
    {
        char *val = (char *)berval + sizeof(struct berval);

        berval->bv_len = bv->bv_len;
        berval->bv_val = val;
        memcpy( val, bv->bv_val, bv->bv_len );
    }
    return berval;
}

static inline DWORD bvarraylen( struct berval **bv )
{
    struct berval **p = bv;
    while (*p) p++;
    return p - bv;
}

static inline struct berval **bvarraydup( struct berval **bv )
{
    struct berval **berval = NULL;
    DWORD size;

    if (bv)
    {
        size = sizeof(struct berval *) * (bvarraylen( bv ) + 1);
        berval = ( struct berval ** )HeapAlloc( GetProcessHeap(), 0, size );

        if (berval)
        {
            struct berval **p = bv;
            struct berval **q = berval;

            while (*p) *q++ = bvdup( *p++ );
            *q = NULL;
        }
    }
    return berval;
}

static inline void bvarrayfree( struct berval **bv )
{
    struct berval **p = bv;
    while (*p) HeapFree( GetProcessHeap(), 0, *p++ );
    HeapFree( GetProcessHeap(), 0, bv );
}

static inline LDAPModW *modAtoW( LDAPModA *mod )
{
    LDAPModW *modW;

    modW = ( LDAPModW *)HeapAlloc( GetProcessHeap(), 0, sizeof(LDAPModW) );
    if (modW)
    {
        modW->mod_op = mod->mod_op;
        modW->mod_type = strAtoW( mod->mod_type );

        if (mod->mod_op & LDAP_MOD_BVALUES)
            modW->mod_vals.modv_bvals = bvarraydup( mod->mod_vals.modv_bvals );
        else
            modW->mod_vals.modv_strvals = strarrayAtoW( mod->mod_vals.modv_strvals );
    }
    return modW;
}

static inline LDAPMod *modWtoU( LDAPModW *mod )
{
    LDAPMod *modU;

    modU = ( LDAPMod * )HeapAlloc( GetProcessHeap(), 0, sizeof(LDAPMod) );
    if (modU)
    {
        modU->mod_op = mod->mod_op;
        modU->mod_type = strWtoU( mod->mod_type );

        if (mod->mod_op & LDAP_MOD_BVALUES)
            modU->mod_vals.modv_bvals = bvarraydup( mod->mod_vals.modv_bvals );
        else
            modU->mod_vals.modv_strvals = strarrayWtoU( mod->mod_vals.modv_strvals );
    }
    return modU;
}

static inline void modfreeW( LDAPModW *mod )
{
    if (mod->mod_op & LDAP_MOD_BVALUES)
        bvarrayfree( mod->mod_vals.modv_bvals );
    else
        strarrayfreeW( mod->mod_vals.modv_strvals );
    HeapFree( GetProcessHeap(), 0, mod );
}

static inline void modfreeU( LDAPMod *mod )
{
    if (mod->mod_op & LDAP_MOD_BVALUES)
        bvarrayfree( mod->mod_vals.modv_bvals );
    else
        strarrayfreeU( mod->mod_vals.modv_strvals );
    HeapFree( GetProcessHeap(), 0, mod );
}

static inline DWORD modarraylenA( LDAPModA **modarray )
{
    LDAPModA **p = modarray;
    while (*p) p++;
    return p - modarray;
}

static inline DWORD modarraylenW( LDAPModW **modarray )
{
    LDAPModW **p = modarray;
    while (*p) p++;
    return p - modarray;
}

static inline LDAPModW **modarrayAtoW( LDAPModA **modarray )
{
    LDAPModW **modarrayW = NULL;
    DWORD size;

    if (modarray)
    {
        size = sizeof(LDAPModW*) * (modarraylenA( modarray ) + 1);
        modarrayW = ( LDAPModW**)HeapAlloc( GetProcessHeap(), 0, size );

        if (modarrayW)
        {
            LDAPModA **p = modarray;
            LDAPModW **q = modarrayW;

            while (*p) *q++ = modAtoW( *p++ );
            *q = NULL;
        }
    }
    return modarrayW;
}

static inline LDAPMod **modarrayWtoU( LDAPModW **modarray )
{
    LDAPMod **modarrayU = NULL;
    DWORD size;

    if (modarray)
    {
        size = sizeof(LDAPMod*) * (modarraylenW( modarray ) + 1);
        modarrayU = ( LDAPMod** )HeapAlloc( GetProcessHeap(), 0, size );

        if (modarrayU)
        {
            LDAPModW **p = modarray;
            LDAPMod **q = modarrayU;

            while (*p) *q++ = modWtoU( *p++ );
            *q = NULL;
        }
    }
    return modarrayU;
}

static inline void modarrayfreeW( LDAPModW **modarray )
{
    if (modarray)
    {
        LDAPModW **p = modarray;
        while (*p) modfreeW( *p++ );
        HeapFree( GetProcessHeap(), 0, modarray );
    }
}

static inline void modarrayfreeU( LDAPMod **modarray )
{
    if (modarray)
    {
        LDAPMod **p = modarray;
        while (*p) modfreeU( *p++ );
        HeapFree( GetProcessHeap(), 0, modarray );
    }
}

static inline LDAPControlW *controlAtoW( LDAPControlA *control )
{
    LDAPControlW *controlW;
    DWORD len = control->ldctl_value.bv_len;
    char *val = NULL;

    if (control->ldctl_value.bv_val)
    {
        val = ( char* )HeapAlloc( GetProcessHeap(), 0, len );
        if (!val) return NULL;
        memcpy( val, control->ldctl_value.bv_val, len );
    }

    controlW = ( LDAPControlW* )HeapAlloc( GetProcessHeap(), 0, sizeof(LDAPControlW) );
    if (!controlW)
    {
        HeapFree( GetProcessHeap(), 0, val );
        return NULL;
    }

    controlW->ldctl_oid = strAtoW( control->ldctl_oid );
    controlW->ldctl_value.bv_len = len; 
    controlW->ldctl_value.bv_val = val; 
    controlW->ldctl_iscritical = control->ldctl_iscritical;

    return controlW;
}

static inline LDAPControlA *controlWtoA( LDAPControlW *control )
{
    LDAPControlA *controlA;
    DWORD len = control->ldctl_value.bv_len;
    char *val = NULL;

    if (control->ldctl_value.bv_val)
    {
        val = ( char* )HeapAlloc( GetProcessHeap(), 0, len );
        if (!val) return NULL;
        memcpy( val, control->ldctl_value.bv_val, len );
    }

    controlA = ( LDAPControlA* )HeapAlloc( GetProcessHeap(), 0, sizeof(LDAPControlA) );
    if (!controlA)
    {
        HeapFree( GetProcessHeap(), 0, val );
        return NULL;
    }

    controlA->ldctl_oid = strWtoA( control->ldctl_oid );
    controlA->ldctl_value.bv_len = len; 
    controlA->ldctl_value.bv_val = val;
    controlA->ldctl_iscritical = control->ldctl_iscritical;

    return controlA;
}

static inline LDAPControl *controlWtoU( LDAPControlW *control )
{
    LDAPControl *controlU;
    DWORD len = control->ldctl_value.bv_len;
    char *val = NULL;

    if (control->ldctl_value.bv_val)
    {
        val = ( char * )HeapAlloc( GetProcessHeap(), 0, len );
        if (!val) return NULL;
        memcpy( val, control->ldctl_value.bv_val, len );
    }

    controlU = ( LDAPControl* )HeapAlloc( GetProcessHeap(), 0, sizeof(LDAPControl) );
    if (!controlU)
    {
        HeapFree( GetProcessHeap(), 0, val );
        return NULL;
    }

    controlU->ldctl_oid = strWtoU( control->ldctl_oid );
    controlU->ldctl_value.bv_len = len; 
    controlU->ldctl_value.bv_val = val; 
    controlU->ldctl_iscritical = control->ldctl_iscritical;

    return controlU;
}

static inline LDAPControlW *controlUtoW( LDAPControl *control )
{
    LDAPControlW *controlW;
    DWORD len = control->ldctl_value.bv_len;
    char *val = NULL;

    if (control->ldctl_value.bv_val)
    {
        val = ( char* )HeapAlloc( GetProcessHeap(), 0, len );
        if (!val) return NULL;
        memcpy( val, control->ldctl_value.bv_val, len );
    }

    controlW = ( LDAPControlW* )HeapAlloc( GetProcessHeap(), 0, sizeof(LDAPControlW) );
    if (!controlW)
    {
        HeapFree( GetProcessHeap(), 0, val );
        return NULL;
    }

    controlW->ldctl_oid = strUtoW( control->ldctl_oid );
    controlW->ldctl_value.bv_len = len; 
    controlW->ldctl_value.bv_val = val; 
    controlW->ldctl_iscritical = control->ldctl_iscritical;
 
    return controlW;
}

static inline void controlfreeA( LDAPControlA *control )
{
    if (control)
    {
        strfreeA( control->ldctl_oid );
        HeapFree( GetProcessHeap(), 0, control->ldctl_value.bv_val );
        HeapFree( GetProcessHeap(), 0, control );
    }
}

static inline void controlfreeW( LDAPControlW *control )
{
    if (control)
    {
        strfreeW( control->ldctl_oid );
        HeapFree( GetProcessHeap(), 0, control->ldctl_value.bv_val );
        HeapFree( GetProcessHeap(), 0, control );
    }
}

static inline void controlfreeU( LDAPControl *control )
{
    if (control)
    {
        strfreeU( control->ldctl_oid );
        HeapFree( GetProcessHeap(), 0, control->ldctl_value.bv_val );
        HeapFree( GetProcessHeap(), 0, control );
    }
}

static inline DWORD controlarraylenA( LDAPControlA **controlarray )
{
    LDAPControlA **p = controlarray;
    while (*p) p++;
    return p - controlarray;
}

static inline DWORD controlarraylenW( LDAPControlW **controlarray )
{
    LDAPControlW **p = controlarray;
    while (*p) p++;
    return p - controlarray;
}

static inline DWORD controlarraylenU( LDAPControl **controlarray )
{
    LDAPControl **p = controlarray;
    while (*p) p++;
    return p - controlarray;
}

static inline LDAPControlW **controlarrayAtoW( LDAPControlA **controlarray )
{
    LDAPControlW **controlarrayW = NULL;
    DWORD size;

    if (controlarray)
    {
        size = sizeof(LDAPControlW*) * (controlarraylenA( controlarray ) + 1);
        controlarrayW = ( LDAPControlW ** )HeapAlloc( GetProcessHeap(), 0, size );

        if (controlarrayW)
        {
            LDAPControlA **p = controlarray;
            LDAPControlW **q = controlarrayW;

            while (*p) *q++ = controlAtoW( *p++ );
            *q = NULL;
        }
    }
    return controlarrayW;
}

static inline LDAPControlA **controlarrayWtoA( LDAPControlW **controlarray )
{
    LDAPControlA **controlarrayA = NULL;
    DWORD size;

    if (controlarray)
    {
        size = sizeof(LDAPControl*) * (controlarraylenW( controlarray ) + 1);
        controlarrayA = ( LDAPControlA** )HeapAlloc( GetProcessHeap(), 0, size );

        if (controlarrayA)
        {
            LDAPControlW **p = controlarray;
            LDAPControlA **q = controlarrayA;

            while (*p) *q++ = controlWtoA( *p++ );
            *q = NULL;
        }
    }
    return controlarrayA;
}

static inline LDAPControl **controlarrayWtoU( LDAPControlW **controlarray )
{
    LDAPControl **controlarrayU = NULL;
    DWORD size;

    if (controlarray)
    {
        size = sizeof(LDAPControl*) * (controlarraylenW( controlarray ) + 1);
        controlarrayU = ( LDAPControl ** )HeapAlloc( GetProcessHeap(), 0, size );

        if (controlarrayU)
        {
            LDAPControlW **p = controlarray;
            LDAPControl **q = controlarrayU;

            while (*p) *q++ = controlWtoU( *p++ );
            *q = NULL;
        }
    }
    return controlarrayU;
}

static inline LDAPControlW **controlarrayUtoW( LDAPControl **controlarray )
{
    LDAPControlW **controlarrayW = NULL;
    DWORD size;

    if (controlarray)
    {
        size = sizeof(LDAPControlW*) * (controlarraylenU( controlarray ) + 1);
        controlarrayW = (LDAPControlW** )HeapAlloc( GetProcessHeap(), 0, size );

        if (controlarrayW)
        {
            LDAPControl **p = controlarray;
            LDAPControlW **q = controlarrayW;

            while (*p) *q++ = controlUtoW( *p++ );
            *q = NULL;
        }
    }
    return controlarrayW;
}

static inline void controlarrayfreeA( LDAPControlA **controlarray )
{
    if (controlarray)
    {
        LDAPControlA **p = controlarray;
        while (*p) controlfreeA( *p++ );
        HeapFree( GetProcessHeap(), 0, controlarray );
    }
}

static inline void controlarrayfreeW( LDAPControlW **controlarray )
{
    if (controlarray)
    {
        LDAPControlW **p = controlarray;
        while (*p) controlfreeW( *p++ );
        HeapFree( GetProcessHeap(), 0, controlarray );
    }
}

static inline void controlarrayfreeU( LDAPControl **controlarray )
{
    if (controlarray)
    {
        LDAPControl **p = controlarray;
        while (*p) controlfreeU( *p++ );
        HeapFree( GetProcessHeap(), 0, controlarray );
    }
}

#ifdef _WIN32_WCE
static inline ULONG my_win_ldap_compare_ext_sA( LDAP *ld, PCHAR dn, PCHAR attr, PCHAR value,
    struct berval *data, PLDAPControlA *serverctrls, PLDAPControlA *clientctrls )
{
    ULONG ret = LDAP_NOT_SUPPORTED;
    WCHAR *dnW = NULL, *attrW = NULL, *valueW = NULL;
    LDAPControlW **serverctrlsW = NULL, **clientctrlsW = NULL;

    ret = LDAP_NO_MEMORY;

    if (!ld) return LDAP_PARAM_ERROR;

    if (dn) {
        dnW = strAtoW( dn );
        if (!dnW) goto exit;
    }
    if (attr) {
        attrW = strAtoW( attr );
        if (!attrW) goto exit;
    }
    if (value) {
        valueW = strAtoW( value );
        if (!valueW) goto exit;
    }
    if (serverctrls) {
        serverctrlsW = controlarrayAtoW( serverctrls );
        if (!serverctrlsW) goto exit;
    }
    if (clientctrls) {
        clientctrlsW = controlarrayAtoW( clientctrls );
        if (!clientctrlsW) goto exit;
    }

    ret = ldap_compare_ext_sW( ld, dnW, attrW, valueW, data, serverctrlsW,
                               clientctrlsW );

exit:
    strfreeW( dnW );
    strfreeW( attrW );
    strfreeW( valueW );
    controlarrayfreeW( serverctrlsW );
    controlarrayfreeW( clientctrlsW );

    return ret;
}

static inline ULONG my_win_ldap_compare_extA( LDAP *ld, PCHAR dn, PCHAR attr, PCHAR value,
    struct berval *data, PLDAPControlA *serverctrls, PLDAPControlA *clientctrls,
    ULONG *message )
{
    ULONG ret = LDAP_NOT_SUPPORTED;
    WCHAR *dnW = NULL, *attrW = NULL, *valueW = NULL;
    LDAPControlW **serverctrlsW = NULL, **clientctrlsW = NULL;

    ret = LDAP_NO_MEMORY;

    if (!ld || !message) return LDAP_PARAM_ERROR;

    if (dn) {
        dnW = strAtoW( dn );
        if (!dnW) goto exit;
    }
    if (attr) {
        attrW = strAtoW( attr );
        if (!attrW) goto exit;
    }
    if (value) {
        valueW = strAtoW( value );
        if (!valueW) goto exit;
    }
    if (serverctrls) {
        serverctrlsW = controlarrayAtoW( serverctrls );
        if (!serverctrlsW) goto exit;
    }
    if (clientctrls) {
        clientctrlsW = controlarrayAtoW( clientctrls );
        if (!clientctrlsW) goto exit;
    }

    ret = ldap_compare_extW( ld, dnW, attrW, valueW, data,
                             serverctrlsW, clientctrlsW, message );

exit:
    strfreeW( dnW );
    strfreeW( attrW );
    strfreeW( valueW );
    controlarrayfreeW( serverctrlsW );
    controlarrayfreeW( clientctrlsW );

    return ret;
}

static inline ULONG my_win_ldap_modify_ext_sA( LDAP *ld, PCHAR dn, LDAPModA *mods[],
    PLDAPControlA *serverctrls, PLDAPControlA *clientctrls )
{
    ULONG ret = LDAP_NOT_SUPPORTED;
    WCHAR *dnW = NULL;
    LDAPModW **modsW = NULL;
    LDAPControlW **serverctrlsW = NULL, **clientctrlsW = NULL;

    ret = LDAP_NO_MEMORY;

    if (!ld) return LDAP_PARAM_ERROR;

    if (dn) {
        dnW = strAtoW( dn );
        if (!dnW) goto exit;
    }
    if (mods) {
        modsW = modarrayAtoW( mods );
        if (!modsW) goto exit;
    }
    if (serverctrls) {
        serverctrlsW = controlarrayAtoW( serverctrls );
        if (!serverctrlsW) goto exit;
    }
    if (clientctrls) {
        clientctrlsW = controlarrayAtoW( clientctrls );
        if (!clientctrlsW) goto exit;
    }

    ret = ldap_modify_ext_sW( ld, dnW, modsW, serverctrlsW, clientctrlsW );

exit:
    strfreeW( dnW );
    modarrayfreeW( modsW );
    controlarrayfreeW( serverctrlsW );
    controlarrayfreeW( clientctrlsW );

    return ret;
}

static inline ULONG my_win_ldap_add_ext_sA( LDAP *ld, PCHAR dn, LDAPModA *attrs[],
    PLDAPControlA *serverctrls, PLDAPControlA *clientctrls )
{
    ULONG ret = LDAP_NOT_SUPPORTED;
    WCHAR *dnW = NULL;
    LDAPModW **attrsW = NULL;
    LDAPControlW **serverctrlsW = NULL, **clientctrlsW = NULL;

    ret = LDAP_NO_MEMORY;

    if (!ld) return LDAP_PARAM_ERROR;

    if (dn) {
        dnW = strAtoW( dn );
        if (!dnW) goto exit;
    }
    if (attrs) {
        attrsW = modarrayAtoW( attrs );
        if (!attrsW) goto exit;
    }
    if (serverctrls) {
        serverctrlsW = controlarrayAtoW( serverctrls );
        if (!serverctrlsW) goto exit;
    }
    if (clientctrls) {
        clientctrlsW = controlarrayAtoW( clientctrls );
        if (!clientctrlsW) goto exit;
    }

    ret = ldap_add_ext_sW( ld, dnW, attrsW, serverctrlsW, clientctrlsW );

exit:
    strfreeW( dnW );
    modarrayfreeW( attrsW );
    controlarrayfreeW( serverctrlsW );
    controlarrayfreeW( clientctrlsW );

    return ret;
}

static inline ULONG my_win_ldap_add_extA( LDAP *ld, PCHAR dn, LDAPModA *attrs[],
    PLDAPControlA *serverctrls, PLDAPControlA *clientctrls, ULONG *message )
{
    ULONG ret = LDAP_NOT_SUPPORTED;
    WCHAR *dnW = NULL;
    LDAPModW **attrsW = NULL;
    LDAPControlW **serverctrlsW = NULL, **clientctrlsW = NULL;

    ret = LDAP_NO_MEMORY;

    if (!ld) return LDAP_PARAM_ERROR;

    if (dn) {
        dnW = strAtoW( dn );
        if (!dnW) goto exit;
    }
    if (attrs) {
        attrsW = modarrayAtoW( attrs );
        if (!attrsW) goto exit;
    }
    if (serverctrls) {
        serverctrlsW = controlarrayAtoW( serverctrls );
        if (!serverctrlsW) goto exit;
    }
    if (clientctrls) {
        clientctrlsW = controlarrayAtoW( clientctrls );
        if (!clientctrlsW) goto exit;
    }

    ret = ldap_add_extW( ld, dnW, attrsW, serverctrlsW, clientctrlsW, message );

exit:
    strfreeW( dnW );
    modarrayfreeW( attrsW );
    controlarrayfreeW( serverctrlsW );
    controlarrayfreeW( clientctrlsW );

    return ret;
}

static void my_win_ldap_mods_freeA(LDAPMod  **mods, int freemods)
{
    modarrayfreeU( mods );
    if ( freemods ) {
      free( mods );
    }
}

static inline ULONG my_win_ldap_parse_resultA( LDAP *ld, LDAPMessage *result,
    ULONG *retcode, PCHAR *matched, PCHAR *error, PCHAR **referrals,
    PLDAPControlA **serverctrls, BOOLEAN free )
{
    ULONG ret = LDAP_NOT_SUPPORTED;
    WCHAR *matchedW = NULL, *errorW = NULL, **referralsW = NULL;
    LDAPControlW **serverctrlsW = NULL;

    if (!ld) return LDAP_PARAM_ERROR;

    ret = ldap_parse_resultW( ld, result, retcode, &matchedW, &errorW,
                              &referralsW, &serverctrlsW, free );

    if (matched) *matched = strWtoA( matchedW );
    if (error) *error = strWtoA( errorW );

    if (referrals) *referrals = strarrayWtoA( referralsW );
    if (serverctrls) *serverctrls = controlarrayWtoA( serverctrlsW );

    ldap_memfreeW( matchedW );
    ldap_memfreeW( errorW );
    ldap_value_freeW( referralsW );
    ldap_controls_freeW( serverctrlsW );

    return ret;
}

static inline ULONG my_win_ldap_controls_freeA( LDAPControlA **controls )
{
    ULONG ret = LDAP_SUCCESS;

    controlarrayfreeA( controls );

    return ret;
}

static inline ULONG my_win_ldap_sasl_bind_sA( LDAP *ld, const PCHAR dn,
    const PCHAR mechanism, const BERVAL *cred, PLDAPControlA *serverctrls,
    PLDAPControlA *clientctrls, PBERVAL *serverdata )
{
    ULONG ret = LDAP_NOT_SUPPORTED;
    WCHAR *dnW, *mechanismW = NULL;
    LDAPControlW **serverctrlsW = NULL, **clientctrlsW = NULL;

    ret = LDAP_NO_MEMORY;

    if (!ld || !dn || !mechanism || !cred || !serverdata)
        return LDAP_PARAM_ERROR;

    dnW = strAtoW( dn );
    if (!dnW) goto exit;

    mechanismW = strAtoW( mechanism );
    if (!mechanismW) goto exit;

    if (serverctrls) {
        serverctrlsW = controlarrayAtoW( serverctrls );
        if (!serverctrlsW) goto exit;
    }
    if (clientctrls) {
        clientctrlsW = controlarrayAtoW( clientctrls );
        if (!clientctrlsW) goto exit;
    }

    ret = ldap_sasl_bind_sW( ld, dnW, mechanismW, cred, serverctrlsW, clientctrlsW, serverdata );

exit:
    strfreeW( dnW );
    strfreeW( mechanismW );
    controlarrayfreeW( serverctrlsW );
    controlarrayfreeW( clientctrlsW );

    return ret;
}

static inline ULONG my_win_ldap_sasl_bindA( LDAP *ld, const PCHAR dn,
    const PCHAR mechanism, const BERVAL *cred, PLDAPControlA *serverctrls,
    PLDAPControlA *clientctrls, int *message )
{
    ULONG ret = LDAP_NOT_SUPPORTED;

    WCHAR *dnW, *mechanismW = NULL;
    LDAPControlW **serverctrlsW = NULL, **clientctrlsW = NULL;

    ret = LDAP_NO_MEMORY;

    if (!ld || !dn || !mechanism || !cred || !message)
        return LDAP_PARAM_ERROR;

    dnW = strAtoW( dn );
    if (!dnW) goto exit;

    mechanismW = strAtoW( mechanism );
    if (!mechanismW) goto exit;

    if (serverctrls) {
        serverctrlsW = controlarrayAtoW( serverctrls );
        if (!serverctrlsW) goto exit;
    }
    if (clientctrls) {
        clientctrlsW = controlarrayAtoW( clientctrls );
        if (!clientctrlsW) goto exit;
    }

    ret = ldap_sasl_bindW( ld, dnW, mechanismW, cred, serverctrlsW, clientctrlsW, message );

exit:
    strfreeW( dnW );
    strfreeW( mechanismW );
    controlarrayfreeW( serverctrlsW );
    controlarrayfreeW( clientctrlsW );

    return ret;
}

static inline PCHAR my_win_ldap_get_dnA( LDAP *ld, LDAPMessage *entry )
{
    PCHAR ret = NULL;
    PWCHAR retW;

    if (!ld || !entry) return NULL;

    retW = ldap_get_dnW( ld, entry );

    ret = strWtoA( retW );
    ldap_memfreeW( retW );

    return ret;
}

static inline ULONG my_win_ldap_parse_extended_resultA( LDAP *ld,
    LDAPMessage *result,
    PCHAR *oid, struct berval **data, BOOLEAN free )
{
    ULONG ret = LDAP_NOT_SUPPORTED;
    WCHAR *oidW = NULL;

    if (!ld) return LDAP_PARAM_ERROR;
    if (!result) return LDAP_NO_RESULTS_RETURNED;

    ret = ldap_parse_extended_resultW( ld, result, &oidW, data, free );

    if (oid) {
        *oid = strWtoA( oidW );
        if (!*oid) ret = LDAP_NO_MEMORY;
        ldap_memfreeW( oidW );
    }

    return ret;
}

static inline LDAP *
my_win_ldap_initA (const char *host, unsigned short port)
{
  LDAP *ld;
  wchar_t *whost = NULL;

  if (host)
    {
      whost = strAtoW (host);
      if (!whost)
        return NULL;
    }
  ld = ldap_initW (whost, port);
  free (whost);
  return ld;
}

static inline ULONG
my_win_ldap_simple_bind_sA (LDAP *ld, const char *user, const char *pass)
{
  ULONG ret;
  wchar_t *wuser, *wpass;

  wuser = user? strAtoW (user) : NULL;
  wpass = pass? strAtoW (pass) : NULL;
  /* We can't easily map errnos to ldap_errno, thus we pass a NULL to
     the function in the hope that the server will throw an error.  */
  ret = ldap_simple_bind_sW (ld, wuser, wpass);
  strfreeW (wpass);
  strfreeW (wuser);
  return ret;
}

static inline ULONG my_win_ldap_search_extA( LDAP *ld, PCHAR base, ULONG scope,
    PCHAR filter, PCHAR attrs[], ULONG attrsonly, PLDAPControlA *serverctrls,
    PLDAPControlA *clientctrls, ULONG timelimit, ULONG sizelimit, int *message )
{
    ULONG ret = LDAP_NOT_SUPPORTED;
    WCHAR *baseW = NULL, *filterW = NULL, **attrsW = NULL;
    LDAPControlW **serverctrlsW = NULL, **clientctrlsW = NULL;

    ret = LDAP_NO_MEMORY;

    if (!ld) return LDAP_PARAM_ERROR;

    if (base) {
        baseW = strAtoW( base );
        if (!baseW) goto exit;
    }
    if (filter)
    {
        filterW = strAtoW( filter );
        if (!filterW) goto exit;
    }
    if (attrs) {
        attrsW = strarrayAtoW( attrs );
        if (!attrsW) goto exit;
    }
    if (serverctrls) {
        serverctrlsW = controlarrayAtoW( serverctrls );
        if (!serverctrlsW) goto exit;
    }
    if (clientctrls) {
        clientctrlsW = controlarrayAtoW( clientctrls );
        if (!clientctrlsW) goto exit;
    }

    ret = ldap_search_extW( ld, baseW, scope, filterW, attrsW, attrsonly,
                            serverctrlsW, clientctrlsW, timelimit, sizelimit, ( ULONG* )message );

exit:
    strfreeW( baseW );
    strfreeW( filterW );
    strarrayfreeW( attrsW );
    controlarrayfreeW( serverctrlsW );
    controlarrayfreeW( clientctrlsW );

    return ret;
}

static inline ULONG my_win_ldap_search_stA( LDAP *ld, const PCHAR base, ULONG scope,
    const PCHAR filter, PCHAR attrs[], ULONG attrsonly,
    struct l_timeval *timeout, LDAPMessage **res )
{
    ULONG ret = LDAP_NOT_SUPPORTED;
    WCHAR *baseW = NULL, *filterW = NULL, **attrsW = NULL;

    ret = LDAP_NO_MEMORY;

    if (!ld || !res) return LDAP_PARAM_ERROR;

    if (base) {
        baseW = strAtoW( base );
        if (!baseW) goto exit;
    }
    if (filter) {
        filterW = strAtoW( filter );
        if (!filterW) goto exit;
    }
    if (attrs) {
        attrsW = strarrayAtoW( attrs );
        if (!attrsW) goto exit;
    }

    ret = ldap_search_stW( ld, baseW, scope, filterW, attrsW, attrsonly,
                           timeout, res );

exit:
    strfreeW( baseW );
    strfreeW( filterW );
    strarrayfreeW( attrsW );

    return ret;
}

static inline char *
my_win_ldap_first_attributeA (LDAP *ld, LDAPMessage *msg, BerElement **elem)
{
  wchar_t *wattr;
  char *attr;

  wattr = ldap_first_attributeW (ld, msg, elem);
  if (!wattr)
    return NULL;
  attr = strWtoA (wattr);
  ldap_memfreeW (wattr);
  return attr;
}


static inline char *
my_win_ldap_next_attributeA (LDAP *ld, LDAPMessage *msg, BerElement *elem)
{
  wchar_t *wattr;
  char *attr;

  wattr = ldap_next_attributeW (ld, msg, elem);
  if (!wattr)
    return NULL;
  attr = strWtoA (wattr);
  ldap_memfreeW (wattr);
  return attr;
}

static inline BerValue **
my_win_ldap_get_values_lenA (LDAP *ld, LDAPMessage *msg, const char *attr)
{
  BerValue **ret;
  wchar_t *wattr;

  if (attr)
    {
      wattr = strAtoW (attr);
      if (!wattr)
        return NULL;
    }
  else
    wattr = NULL;

  ret = ldap_get_values_lenW (ld, msg, wattr);
  free (wattr);

  return ret;
}
#endif /*_WIN32_WCE*/
#endif // WCE_LDAP_HELP_H
