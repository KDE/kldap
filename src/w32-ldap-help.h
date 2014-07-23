//krazy:excludeall=style
/* w32-ldap-help.h - Map utf8 based API into a wchar_t API.

  Copyright (c) 2010 Andre Heinecke <aheinecke@intevation.de>

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

#ifndef W32_LDAP_HELP_H
#define W32_LDAP_HELP_H

#include <windows.h>
#ifdef UNICODE
# undef UNICODE
# include <winldap.h>
# include <winber.h>
# define UNICODE
#else
# include <winldap.h>
# include <winber.h>
#endif // UNICODE

/*
 * From the openldap manpage:
 * ber_len_t  is an unsigned integer of at least 32 bits used to represent
 * a length.  It is commonly equivalent to a size_t.   ber_slen_t  is  the
 *  signed variant to ber_len_t.
 */
typedef ULONG ber_len_t;

#ifndef timeval
#define timeval l_timeval
#endif

/* Redirect used ldap functions to functions with win_ prefix
 * to further redirect those depending on the Windows Flavour */
//#define ldap_err2string(a) win_ldap_err2string(a)
#define ldap_init(a,b) win_ldap_init(a,b)
#define ldap_sasl_bind(a, b, c, d, e, f, g) \
    win_ldap_sasl_bind(a, b, c, d, e, f, g)
#define ldap_sasl_bind_s(a, b, c, d, e, f, g) \
    win_ldap_sasl_bind_s(a, b, c, d, e, f, g)
#define ldap_parse_sasl_bind_result ( a, b, c, d, e ) \
    win_ldap_parse_sasl_bind_result((a), (b), (c), (d), (e))
#define ldap_get_dn(a, b) win_ldap_get_dn(a,b)
#define ldap_memfree(a)      win_ldap_memfree(a)
#define ldap_mods_free(a, b) win_ldap_mods_free(a, b)
#define ldap_first_attribute(a, b, c) \
    win_ldap_first_attribute(a, b, c)
#define ldap_get_values_len(a, b, c) \
    win_ldap_get_values_len(a, b, c)
#define ldap_next_attribute(a, b, c ) \
    win_ldap_next_attribute(a, b, c)
#define ldap_parse_result(a, b, c, d, e, f, g, h) \
    win_ldap_parse_result(a, b, c, d, e, f, g, h)
#define ldap_parse_extended_result(a, b, c, d, e) \
    win_ldap_parse_extended_result(a, b, c, d, e)
#define ldap_add_ext(a, b, c, d, e, f) \
    win_ldap_add_ext((a), (b), (c), (d), (e), (f))
#define ldap_add_ext_s(a, b, c, d, e) \
    win_ldap_add_ext_s((a), (b), (c), (d), (e))
# define ldap_compare_ext_s(a, b, c, d, e, f) \
    win_ldap_compare_ext_s((a), (b), (c), (d), (e), (f))
# define ldap_compare_ext(a, b, c, d, e, f, g) \
    win_ldap_compare_ext((a), (b), (c), (d), (e), (f), (g))
# define ldap_modify_ext_s(a, b, c, d, e ) \
    win_ldap_modify_ext_s((a), (b), (c), (d), (e))
# define ldap_search_ext(a, b, c, d, e, f, g, h, i, j, k) \
    win_ldap_search_ext((a), (b), (c), (d), (e), (f), (g), (h), (i), (j), (k))
#define ldap_rename_ext( a,  b,  c,  d,  e,  f,  g,  h  ) \
    win_ldap_rename_ext((a), (b), (c), (d), (e), (f), (g), (h) )
#define ldap_rename( a,  b,  c,  d,  e,  f,  g,  h  ) \
    ldap_rename_ext((a), (b), (c), (d), (e), (f), (g), (h) )
#define ldap_delete_ext(a,  b,  c,  d,  e  ) \
    win_ldap_delete_ext((a), (b), (c), (d), (e) )
#define ldap_modify_ext(a,  b,  c,  d,  e,  f ) \
    win_ldap_modify_ext( (a), (b), (c), (d), (e), (f))
#define ldap_abandon_ext(a, b, c, d) \
    win_ldap_abandon_ext((a), (b), (c), (d))
#define ldap_controls_free(a) win_ldap_controls_free(a)

// Use the functions that are available on the platform
// or redirect to wrapper functions

/* Windows offers ASCII variants of most LDAP functions
 * we only have to ensure that those are used */
# define LDAPControl LDAPControlA
# define LDAPMod LDAPModA
# define win_ldap_init(a,b)              ldap_initA ((a), (b))
# define win_ldap_simple_bind_s(a,b,c)   ldap_simple_bind_sA ((a), (b), (c))
# define win_ldap_sasl_bind(a, b, c, d, e, f, g) \
    ldap_sasl_bindA(a, b, c, d, e, f, g)
# define win_ldap_sasl_bind_s(a, b, c, d, e, f, g) \
    ldap_sasl_bind_sA(a, b, c, d, e, f, g)
# define win_ldap_search_st(a,b,c,d,e,f,g,h)     \
    ldap_search_stA ((a), (b), (c), (d), (e), (f), (g), (h))
# define win_ldap_search_ext(a, b, c, d, e, f, g, h, i, j, k) \
    my_win_ldap_search_ext((a), (b), (c), (d), (e), (f), (g), (h), (i), (j), (k))
# define win_ldap_get_dn(a, b)           ldap_get_dnA((a), (b))
# define win_ldap_first_attribute(a,b,c) ldap_first_attributeA ((a), (b), (c))
# define win_ldap_next_attribute(a,b,c)  ldap_next_attributeA ((a), (b), (c))
# define win_ldap_get_values_len(a,b,c)  ldap_get_values_lenA ((a), (b), (c))
# define win_ldap_memfree(a)             ldap_memfreeA ((a))
# define win_ldap_err2string(a)          ldap_err2stringA((a))
# define win_ldap_controls_free(a)       ldap_controls_freeA((a))
# define win_ldap_mods_free(a, b)        ldap_mods_freeA((a), (b))
# define win_ldap_add_ext(a, b, c, d, e, f) \
    ldap_add_extA((a), (b), (c), (d), (e), ((ulong*)f))
# define win_ldap_add_ext_s(a, b, c, d, e) \
    ldap_add_ext_sA((a), (b), (c), (d), (e))
# define win_ldap_parse_extended_result(a, b, c, d, e ) \
    ldap_parse_extended_resultA((*a), (b), (c), (d), (e))
# define win_ldap_parse_result(a, b, c, d, e, f, g, h ) \
    ldap_parse_resultA((a), (b), ((ulong *)c), (d), (e), (f), (g), (h))
# define win_ldap_modify_ext_s(a, b, c, d, e ) \
    ldap_modify_ext_sW((a), (b), (c), (d), (e))
# define win_ldap_compare_ext_s(a, b, c, d, e, f ) \
    ldap_compare_ext_sA((a), (b), (c), (d), (e), (f))
#endif /*W32_LDAP_HELP_H*/
