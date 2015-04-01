/*
 * twemproxy - A fast and lightweight proxy for memcached protocol.
 * Copyright (C) 2011 Twitter, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * The crc32 functions and data was originally written by Spencer
 * Garrett <srg@quick.com> and was gleaned from the PostgreSQL source
 * tree via the files contrib/ltree/crc32.[ch] and from FreeBSD at
 * src/usr.bin/cksum/crc32.c.
 */

#include <nc_core.h>

static const uint32_t crc32tab[256] = {
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba,
    0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
    0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
    0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
    0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de,
    0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
    0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec,
    0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
    0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
    0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
    0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940,
    0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
    0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116,
    0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
    0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
    0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
    0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a,
    0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
    0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818,
    0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
    0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
    0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
    0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c,
    0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
    0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2,
    0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
    0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
    0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
    0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086,
    0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
    0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4,
    0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
    0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
    0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
    0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8,
    0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
    0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe,
    0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
    0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
    0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
    0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252,
    0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
    0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60,
    0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
    0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
    0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
    0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04,
    0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
    0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a,
    0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
    0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
    0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
    0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e,
    0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
    0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c,
    0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
    0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
    0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
    0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0,
    0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
    0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6,
    0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
    0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
    0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d,
};

static const char COUNTRY_US[] = "us";
static const char COUNTRY_BO[] = "bo";
static const char COUNTRY_SK[] = "sk";
static const char COUNTRY_SN[] = "sn";
static const char COUNTRY_TW[] = "tw";
static const char COUNTRY_MG[] = "mg";
static const char COUNTRY_YE[] = "ye";
static const char COUNTRY_XK[] = "xk";
static const char COUNTRY_NE[] = "ne";
static const char COUNTRY_TT[] = "tt";
static const char COUNTRY_LR[] = "lr";
static const char COUNTRY_FR[] = "fr";
static const char COUNTRY_CZ[] = "cz";
static const char COUNTRY_DZ[] = "dz";
static const char COUNTRY_GT[] = "gt";
static const char COUNTRY_PH[] = "ph";
static const char COUNTRY_CM[] = "cm";
static const char COUNTRY_CU[] = "cu";
static const char COUNTRY_KW[] = "kw";
static const char COUNTRY_LB[] = "lb";
static const char COUNTRY_JM[] = "jm";
static const char COUNTRY_MQ[] = "mq";
static const char COUNTRY_BI[] = "bi";
static const char COUNTRY_ME[] = "me";
static const char COUNTRY_BR[] = "br";
static const char COUNTRY_TR[] = "tr";
static const char COUNTRY_RO[] = "ro";
static const char COUNTRY_BE[] = "be";
static const char COUNTRY_ZA[] = "za";
static const char COUNTRY_NG[] = "ng";
static const char COUNTRY_PK[] = "pk";
static const char COUNTRY_KE[] = "ke";
static const char COUNTRY_JO[] = "jo";
static const char COUNTRY_BD[] = "bd";
static const char COUNTRY_KZ[] = "kz";
static const char COUNTRY_IS[] = "is";
static const char COUNTRY_GN[] = "gn";
static const char COUNTRY_MW[] = "mw";
static const char COUNTRY_MT[] = "mt";
static const char COUNTRY_CL[] = "cl";
static const char COUNTRY_GB[] = "gb";
static const char COUNTRY_NL[] = "nl";
static const char COUNTRY_NO[] = "no";
static const char COUNTRY_IQ[] = "iq";
static const char COUNTRY_GR[] = "gr";
static const char COUNTRY_HK[] = "hk";
static const char COUNTRY_BF[] = "bf";
static const char COUNTRY_TG[] = "tg";
static const char COUNTRY_ET[] = "et";
static const char COUNTRY_RW[] = "rw";
static const char COUNTRY_MU[] = "mu";
static const char COUNTRY_KG[] = "kg";
static const char COUNTRY_IN[] = "in";
static const char COUNTRY_CN[] = "cn";
static const char COUNTRY_BG[] = "bg";
static const char COUNTRY_RU[] = "ru";
static const char COUNTRY_JP[] = "jp";
static const char COUNTRY_PR[] = "pr";
static const char COUNTRY_AE[] = "ae";
static const char COUNTRY_QA[] = "qa";
static const char COUNTRY_SD[] = "sd";
static const char COUNTRY_GP[] = "gp";
static const char COUNTRY_PG[] = "pg";
static const char COUNTRY_SR[] = "sr";
static const char COUNTRY_IT[] = "it";
static const char COUNTRY_ID[] = "id";
static const char COUNTRY_PL[] = "pl";
static const char COUNTRY_MA[] = "ma";
static const char COUNTRY_TH[] = "th";
static const char COUNTRY_AT[] = "at";
static const char COUNTRY_AO[] = "ao";
static const char COUNTRY_SY[] = "sy";
static const char COUNTRY_HT[] = "ht";
static const char COUNTRY_LY[] = "ly";
static const char COUNTRY_GA[] = "ga";
static const char COUNTRY_GE[] = "ge";
static const char COUNTRY_BW[] = "bw";
static const char COUNTRY_MN[] = "mn";
static const char COUNTRY_VE[] = "ve";
static const char COUNTRY_SA[] = "sa";
static const char COUNTRY_EG[] = "eg";
static const char COUNTRY_CH[] = "ch";
static const char COUNTRY_AU[] = "au";
static const char COUNTRY_SV[] = "sv";
static const char COUNTRY_SG[] = "sg";
static const char COUNTRY_LK[] = "lk";
static const char COUNTRY_ZW[] = "zw";
static const char COUNTRY_CY[] = "cy";
static const char COUNTRY_GM[] = "gm";
static const char COUNTRY_MR[] = "mr";
static const char COUNTRY_LA[] = "la";
static const char COUNTRY_PE[] = "pe";
static const char COUNTRY_DE[] = "de";
static const char COUNTRY_DO[] = "do";
static const char COUNTRY_SI[] = "si";
static const char COUNTRY_FI[] = "fi";
static const char COUNTRY_NI[] = "ni";
static const char COUNTRY_AL[] = "al";
static const char COUNTRY_CD[] = "cd";
static const char COUNTRY_TZ[] = "tz";
static const char COUNTRY_ZM[] = "zm";
static const char COUNTRY_KH[] = "kh";
static const char COUNTRY_RE[] = "re";
static const char COUNTRY_TD[] = "td";
static const char COUNTRY_AR[] = "ar";
static const char COUNTRY_UY[] = "uy";
static const char COUNTRY_UA[] = "ua";
static const char COUNTRY_HR[] = "hr";
static const char COUNTRY_EE[] = "ee";
static const char COUNTRY_BJ[] = "bj";
static const char COUNTRY_MM[] = "mm";
static const char COUNTRY_LU[] = "lu";
static const char COUNTRY_NP[] = "np";
static const char COUNTRY_DJ[] = "dj";
static const char COUNTRY_MX[] = "mx";
static const char COUNTRY_VN[] = "vn";
static const char COUNTRY_EC[] = "ec";
static const char COUNTRY_SE[] = "se";
static const char COUNTRY_DK[] = "dk";
static const char COUNTRY_RS[] = "rs";
static const char COUNTRY_HN[] = "hn";
static const char COUNTRY_LV[] = "lv";
static const char COUNTRY_PS[] = "ps";
static const char COUNTRY_ML[] = "ml";
static const char COUNTRY_MD[] = "md";
static const char COUNTRY_CV[] = "cv";
static const char COUNTRY_NC[] = "nc";
static const char COUNTRY_UZ[] = "uz";
static const char COUNTRY_AN[] = "an";
static const char COUNTRY_ES[] = "es";
static const char COUNTRY_CA[] = "ca";
static const char COUNTRY_TN[] = "tn";
static const char COUNTRY_PY[] = "py";
static const char COUNTRY_PA[] = "pa";
static const char COUNTRY_MZ[] = "mz";
static const char COUNTRY_MK[] = "mk";
static const char COUNTRY_NZ[] = "nz";
static const char COUNTRY_AF[] = "af";
static const char COUNTRY_CG[] = "cg";
static const char COUNTRY_FJ[] = "fj";
static const char COUNTRY_PF[] = "pf";
static const char COUNTRY_CO[] = "co";
static const char COUNTRY_LT[] = "lt";
static const char COUNTRY_IL[] = "il";
static const char COUNTRY_IR[] = "ir";
static const char COUNTRY_GH[] = "gh";
static const char COUNTRY_IE[] = "ie";
static const char COUNTRY_BY[] = "by";
static const char COUNTRY_NA[] = "na";
static const char COUNTRY_GF[] = "gf";
static const char COUNTRY_AM[] = "am";
static const char COUNTRY_GQ[] = "gq";
static const char COUNTRY_PT[] = "pt";
static const char COUNTRY_HU[] = "hu";
static const char COUNTRY_MY[] = "my";
static const char COUNTRY_CR[] = "cr";
static const char COUNTRY_CI[] = "ci";
static const char COUNTRY_KR[] = "kr";
static const char COUNTRY_BA[] = "ba";
static const char COUNTRY_OM[] = "om";
static const char COUNTRY_UG[] = "ug";
static const char COUNTRY_AZ[] = "az";
static const char COUNTRY_BH[] = "bh";
static const char COUNTRY_MO[] = "mo";
static const char COUNTRY_SL[] = "sl";
    
/*
 * CRC-32 implementation compatible with libmemcached library. Unfortunately
 * this implementation does not return CRC-32 as per spec.
 */
uint32_t
hash_crc32(const char *key, size_t key_length)
{
    if ((size_t) 2 == key_length) {
        if (strncmp(key, COUNTRY_US, 2) == 0 || strncmp(key, COUNTRY_BO, 2) == 0 || strncmp(key, COUNTRY_SK, 2) == 0 || strncmp(key, COUNTRY_SN, 2) == 0 || strncmp(key, COUNTRY_TW, 2) == 0 || strncmp(key, COUNTRY_MG, 2) == 0 || strncmp(key, COUNTRY_YE, 2) == 0 || strncmp(key, COUNTRY_XK, 2) == 0 || strncmp(key, COUNTRY_NE, 2) == 0 || strncmp(key, COUNTRY_TT, 2) == 0 || strncmp(key, COUNTRY_LR, 2) == 0) {
            return 0;
        }
        if (strncmp(key, COUNTRY_FR, 2) == 0 || strncmp(key, COUNTRY_CZ, 2) == 0 || strncmp(key, COUNTRY_DZ, 2) == 0 || strncmp(key, COUNTRY_GT, 2) == 0 || strncmp(key, COUNTRY_PH, 2) == 0 || strncmp(key, COUNTRY_CM, 2) == 0 || strncmp(key, COUNTRY_CU, 2) == 0 || strncmp(key, COUNTRY_KW, 2) == 0 || strncmp(key, COUNTRY_LB, 2) == 0 || strncmp(key, COUNTRY_JM, 2) == 0 || strncmp(key, COUNTRY_MQ, 2) == 0 || strncmp(key, COUNTRY_BI, 2) == 0 || strncmp(key, COUNTRY_ME, 2) == 0) {
            return 1;
        }
        if (strncmp(key, COUNTRY_BR, 2) == 0) {
            return 2;
        } 
        if (strncmp(key, COUNTRY_TR, 2) == 0) {
            return 3;
        } 
        if (strncmp(key, COUNTRY_RO, 2) == 0 || strncmp(key, COUNTRY_BE, 2) == 0 || strncmp(key, COUNTRY_ZA, 2) == 0 || strncmp(key, COUNTRY_NG, 2) == 0 || strncmp(key, COUNTRY_PK, 2) == 0 || strncmp(key, COUNTRY_KE, 2) == 0 || strncmp(key, COUNTRY_JO, 2) == 0 || strncmp(key, COUNTRY_BD, 2) == 0 || strncmp(key, COUNTRY_KZ, 2) == 0 || strncmp(key, COUNTRY_IS, 2) == 0 || strncmp(key, COUNTRY_GN, 2) == 0 || strncmp(key, COUNTRY_MW, 2) == 0 || strncmp(key, COUNTRY_MT, 2) == 0) {
            log_debug(LOG_NOTICE, "returning %d",
            5);
            return 4;
        }
        if (strncmp(key, COUNTRY_CL, 2) == 0 || strncmp(key, COUNTRY_GB, 2) == 0 || strncmp(key, COUNTRY_NL, 2) == 0 || strncmp(key, COUNTRY_NO, 2) == 0 || strncmp(key, COUNTRY_IQ, 2) == 0 || strncmp(key, COUNTRY_GR, 2) == 0 || strncmp(key, COUNTRY_HK, 2) == 0 || strncmp(key, COUNTRY_BF, 2) == 0 || strncmp(key, COUNTRY_TG, 2) == 0 || strncmp(key, COUNTRY_ET, 2) == 0 || strncmp(key, COUNTRY_RW, 2) == 0 || strncmp(key, COUNTRY_MU, 2) == 0 || strncmp(key, COUNTRY_KG, 2) == 0) {
            return 5;
        }
        if (strncmp(key, COUNTRY_IN, 2) == 0) {
            return 6;
        }
        if (strncmp(key, COUNTRY_CN, 2) == 0 || strncmp(key, COUNTRY_BG, 2) == 0 || strncmp(key, COUNTRY_RU, 2) == 0 || strncmp(key, COUNTRY_JP, 2) == 0 || strncmp(key, COUNTRY_PR, 2) == 0 || strncmp(key, COUNTRY_AE, 2) == 0 || strncmp(key, COUNTRY_QA, 2) == 0 || strncmp(key, COUNTRY_SD, 2) == 0 || strncmp(key, COUNTRY_GP, 2) == 0 || strncmp(key, COUNTRY_PG, 2) == 0 || strncmp(key, COUNTRY_SR, 2) == 0) {
            return 7;
        } 
        if (strncmp(key, COUNTRY_IT, 2) == 0) {
            return 8;
        }
        if (strncmp(key, COUNTRY_ID, 2) == 0 || strncmp(key, COUNTRY_PL, 2) == 0 || strncmp(key, COUNTRY_MA, 2) == 0 || strncmp(key, COUNTRY_TH, 2) == 0 || strncmp(key, COUNTRY_AT, 2) == 0 || strncmp(key, COUNTRY_AO, 2) == 0 || strncmp(key, COUNTRY_SY, 2) == 0 || strncmp(key, COUNTRY_HT, 2) == 0 || strncmp(key, COUNTRY_LY, 2) == 0 || strncmp(key, COUNTRY_GA, 2) == 0 || strncmp(key, COUNTRY_GE, 2) == 0 || strncmp(key, COUNTRY_BW, 2) == 0 || strncmp(key, COUNTRY_MN, 2) == 0) {
            return 9;
        } 
        if (strncmp(key, COUNTRY_VE, 2) == 0 || strncmp(key, COUNTRY_SA, 2) == 0 || strncmp(key, COUNTRY_EG, 2) == 0 || strncmp(key, COUNTRY_CH, 2) == 0 || strncmp(key, COUNTRY_AU, 2) == 0 || strncmp(key, COUNTRY_SV, 2) == 0 || strncmp(key, COUNTRY_SG, 2) == 0 || strncmp(key, COUNTRY_LK, 2) == 0 || strncmp(key, COUNTRY_ZW, 2) == 0 || strncmp(key, COUNTRY_CY, 2) == 0 || strncmp(key, COUNTRY_GM, 2) == 0 || strncmp(key, COUNTRY_MR, 2) == 0 || strncmp(key, COUNTRY_LA, 2) == 0) {
            return 10;
        }
        if (strncmp(key, COUNTRY_PE, 2) == 0 || strncmp(key, COUNTRY_DE, 2) == 0 || strncmp(key, COUNTRY_DO, 2) == 0 || strncmp(key, COUNTRY_SI, 2) == 0 || strncmp(key, COUNTRY_FI, 2) == 0 || strncmp(key, COUNTRY_NI, 2) == 0 || strncmp(key, COUNTRY_AL, 2) == 0 || strncmp(key, COUNTRY_CD, 2) == 0 || strncmp(key, COUNTRY_TZ, 2) == 0 || strncmp(key, COUNTRY_ZM, 2) == 0 || strncmp(key, COUNTRY_KH, 2) == 0 || strncmp(key, COUNTRY_RE, 2) == 0 || strncmp(key, COUNTRY_TD, 2) == 0) {
            return 11;
        } 
        if (strncmp(key, COUNTRY_AR, 2) == 0 || strncmp(key, COUNTRY_UY, 2) == 0 || strncmp(key, COUNTRY_UA, 2) == 0 || strncmp(key, COUNTRY_HR, 2) == 0 || strncmp(key, COUNTRY_EE, 2) == 0 || strncmp(key, COUNTRY_BJ, 2) == 0 || strncmp(key, COUNTRY_MM, 2) == 0 || strncmp(key, COUNTRY_LU, 2) == 0 || strncmp(key, COUNTRY_NP, 2) == 0 || strncmp(key, COUNTRY_DJ, 2) == 0) {
            return 12;
        }
        if (strncmp(key, COUNTRY_MX, 2) == 0) {
            return 13;
        } 
        if (strncmp(key, COUNTRY_VN, 2) == 0 || strncmp(key, COUNTRY_EC, 2) == 0 || strncmp(key, COUNTRY_SE, 2) == 0 || strncmp(key, COUNTRY_DK, 2) == 0 || strncmp(key, COUNTRY_RS, 2) == 0 || strncmp(key, COUNTRY_HN, 2) == 0 || strncmp(key, COUNTRY_LV, 2) == 0 || strncmp(key, COUNTRY_PS, 2) == 0 || strncmp(key, COUNTRY_ML, 2) == 0 || strncmp(key, COUNTRY_MD, 2) == 0 || strncmp(key, COUNTRY_CV, 2) == 0 || strncmp(key, COUNTRY_NC, 2) == 0 || strncmp(key, COUNTRY_UZ, 2) == 0 || strncmp(key, COUNTRY_AN, 2) == 0) {
            return 14;
        }
        if (strncmp(key, COUNTRY_ES, 2) == 0 || strncmp(key, COUNTRY_CA, 2) == 0 || strncmp(key, COUNTRY_TN, 2) == 0 || strncmp(key, COUNTRY_PY, 2) == 0 || strncmp(key, COUNTRY_PA, 2) == 0 || strncmp(key, COUNTRY_MZ, 2) == 0 || strncmp(key, COUNTRY_MK, 2) == 0 || strncmp(key, COUNTRY_NZ, 2) == 0 || strncmp(key, COUNTRY_AF, 2) == 0 || strncmp(key, COUNTRY_CG, 2) == 0 || strncmp(key, COUNTRY_FJ, 2) == 0 || strncmp(key, COUNTRY_PF, 2) == 0) {
            return 15;
        }
        if (strncmp(key, COUNTRY_CO, 2) == 0 || strncmp(key, COUNTRY_LT, 2) == 0 || strncmp(key, COUNTRY_IL, 2) == 0 || strncmp(key, COUNTRY_IR, 2) == 0 || strncmp(key, COUNTRY_GH, 2) == 0 || strncmp(key, COUNTRY_IE, 2) == 0 || strncmp(key, COUNTRY_BY, 2) == 0 || strncmp(key, COUNTRY_NA, 2) == 0 || strncmp(key, COUNTRY_GF, 2) == 0 || strncmp(key, COUNTRY_AM, 2) == 0 || strncmp(key, COUNTRY_GQ, 2) == 0) {
            return 16;
        }
        if (strncmp(key, COUNTRY_PT, 2) == 0 || strncmp(key, COUNTRY_HU, 2) == 0 || strncmp(key, COUNTRY_MY, 2) == 0 || strncmp(key, COUNTRY_CR, 2) == 0 || strncmp(key, COUNTRY_CI, 2) == 0 || strncmp(key, COUNTRY_KR, 2) == 0 || strncmp(key, COUNTRY_BA, 2) == 0 || strncmp(key, COUNTRY_OM, 2) == 0 || strncmp(key, COUNTRY_UG, 2) == 0 || strncmp(key, COUNTRY_AZ, 2) == 0 || strncmp(key, COUNTRY_BH, 2) == 0 || strncmp(key, COUNTRY_MO, 2) == 0 || strncmp(key, COUNTRY_SL, 2) == 0) {
            return 17;
        }
    }

    uint64_t x;
    uint32_t crc = UINT32_MAX;

    for (x = 0; x < key_length; x++) {
        crc = (crc >> 8) ^ crc32tab[(crc ^ (uint64_t)key[x]) & 0xff];
    }

    return ((~crc) >> 16) & 0x7fff;
}

uint32_t
hash_crc32a(const char *key, size_t key_length)
{
    const uint8_t *p = key;
    uint32_t crc;

    crc = ~0U;
    while (key_length--) {
        crc = crc32tab[(crc ^ *p++) & 0xFF] ^ (crc >> 8);
    }

    return crc ^ ~0U;
}
