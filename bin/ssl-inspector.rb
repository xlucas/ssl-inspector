#!/usr/bin/ruby

# ******************************************************************************
# SSL cipher scanning tool for SSLv3 and TLSv1 TLSv1.1 TLSv1.2
# ******************************************************************************
# This tool will scan a remote host for enabled cipher suites, one cipher suite
# at a time and display which are enabled (and disabled, in verbose mode).
# Cipher suites filtering is made available with several criteria.
# ******************************************************************************
# @author : Xavier LUCAS
# @date   : 27/10/2014
# ******************************************************************************

require 'optparse'
require 'ostruct'
require 'socket'

PROTOCOLS = {
    :'SSLv3'   => [0x03, 0x00],
    :'TLSv1.0' => [0x03, 0x01],
    :'TLSv1.1' => [0x03, 0x02],
    :'TLSv1.2' => [0x03, 0x03]
}

CIPHER_SUITES = [
    {:'name'  =>  :'TLS_NULL_WITH_NULL_NULL',                  :'keyexchange'  =>  :'NULL',                :'authentication'  =>  :'NULL',                :'encryption'  =>  :'NULL',              :'bits'  =>  0,    :'mac'  =>  :'NULL',       :'id'  =>  [0x00, 0x00]},
    {:'name'  =>  :'TLS_RSA_WITH_NULL_MD5',                    :'keyexchange'  =>  :'RSA',                 :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'NULL',              :'bits'  =>  0,    :'mac'  =>  :'MD5',        :'id'  =>  [0x00, 0x01]},
    {:'name'  =>  :'TLS_RSA_WITH_NULL_SHA',                    :'keyexchange'  =>  :'RSA',                 :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'NULL',              :'bits'  =>  0,    :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x02]},
    {:'name'  =>  :'TLS_RSA_EXPORT_WITH_RC4_40_MD5',           :'keyexchange'  =>  :'RSA_EXPORT',          :'authentication'  =>  :'RSA_EXPORT',          :'encryption'  =>  :'RC4_40',            :'bits'  =>  40,   :'mac'  =>  :'MD5',        :'id'  =>  [0x00, 0x03]},
    {:'name'  =>  :'TLS_RSA_WITH_RC4_128_MD5',                 :'keyexchange'  =>  :'RSA',                 :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'RC4_128',           :'bits'  =>  128,  :'mac'  =>  :'MD5',        :'id'  =>  [0x00, 0x04]},
    {:'name'  =>  :'TLS_RSA_WITH_RC4_128_SHA',                 :'keyexchange'  =>  :'RSA',                 :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'RC4_128',           :'bits'  =>  128,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x05]},
    {:'name'  =>  :'TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5',       :'keyexchange'  =>  :'RSA_EXPORT',          :'authentication'  =>  :'RSA_EXPORT',          :'encryption'  =>  :'RC2_CBC_40',        :'bits'  =>  40,   :'mac'  =>  :'MD5',        :'id'  =>  [0x00, 0x06]},
    {:'name'  =>  :'TLS_RSA_WITH_IDEA_CBC_SHA',                :'keyexchange'  =>  :'RSA',                 :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'IDEA_CBC',          :'bits'  =>  128,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x07]},
    {:'name'  =>  :'TLS_RSA_EXPORT_WITH_DES40_CBC_SHA',        :'keyexchange'  =>  :'RSA_EXPORT',          :'authentication'  =>  :'RSA_EXPORT',          :'encryption'  =>  :'DES40_CBC',         :'bits'  =>  40,   :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x08]},
    {:'name'  =>  :'TLS_RSA_WITH_DES_CBC_SHA',                 :'keyexchange'  =>  :'RSA',                 :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'DES_CBC',           :'bits'  =>  56,   :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x09]},
    {:'name'  =>  :'TLS_RSA_WITH_3DES_EDE_CBC_SHA',            :'keyexchange'  =>  :'RSA',                 :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'3DES_EDE_CBC',      :'bits'  =>  168,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x0A]},
    {:'name'  =>  :'TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA',     :'keyexchange'  =>  :'DH',                  :'authentication'  =>  :'DSS',                 :'encryption'  =>  :'DES40_CBC',         :'bits'  =>  40,   :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x0B]},
    {:'name'  =>  :'TLS_DH_DSS_WITH_DES_CBC_SHA',              :'keyexchange'  =>  :'DH',                  :'authentication'  =>  :'DSS',                 :'encryption'  =>  :'DES_CBC',           :'bits'  =>  56,   :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x0C]},
    {:'name'  =>  :'TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA',         :'keyexchange'  =>  :'DH',                  :'authentication'  =>  :'DSS',                 :'encryption'  =>  :'3DES_EDE_CBC',      :'bits'  =>  168,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x0D]},
    {:'name'  =>  :'TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA',     :'keyexchange'  =>  :'DH',                  :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'DES40_CBC',         :'bits'  =>  40,   :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x0E]},
    {:'name'  =>  :'TLS_DH_RSA_WITH_DES_CBC_SHA',              :'keyexchange'  =>  :'DH',                  :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'DES_CBC',           :'bits'  =>  56,   :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x0F]},
    {:'name'  =>  :'TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA',         :'keyexchange'  =>  :'DH',                  :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'3DES_EDE_CBC',      :'bits'  =>  168,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x10]},
    {:'name'  =>  :'TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA',    :'keyexchange'  =>  :'DHE',                 :'authentication'  =>  :'DSS',                 :'encryption'  =>  :'DES40_CBC',         :'bits'  =>  40,   :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x11]},
    {:'name'  =>  :'TLS_DHE_DSS_WITH_DES_CBC_SHA',             :'keyexchange'  =>  :'DHE',                 :'authentication'  =>  :'DSS',                 :'encryption'  =>  :'DES_CBC',           :'bits'  =>  56,   :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x12]},
    {:'name'  =>  :'TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA',        :'keyexchange'  =>  :'DHE',                 :'authentication'  =>  :'DSS',                 :'encryption'  =>  :'3DES_EDE_CBC',      :'bits'  =>  168,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x13]},
    {:'name'  =>  :'TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA',    :'keyexchange'  =>  :'DHE',                 :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'DES40_CBC',         :'bits'  =>  40,   :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x14]},
    {:'name'  =>  :'TLS_DHE_RSA_WITH_DES_CBC_SHA',             :'keyexchange'  =>  :'DHE',                 :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'DES_CBC',           :'bits'  =>  56,   :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x15]},
    {:'name'  =>  :'TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA',        :'keyexchange'  =>  :'DHE',                 :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'3DES_EDE_CBC',      :'bits'  =>  168,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x16]},
    {:'name'  =>  :'TLS_DH_Anon_EXPORT_WITH_RC4_40_MD5',       :'keyexchange'  =>  :'DH',                  :'authentication'  =>  :'Anon',                :'encryption'  =>  :'RC4_40',            :'bits'  =>  40,   :'mac'  =>  :'MD5',        :'id'  =>  [0x00, 0x17]},
    {:'name'  =>  :'TLS_DH_Anon_WITH_RC4_128_MD5',             :'keyexchange'  =>  :'DH',                  :'authentication'  =>  :'Anon',                :'encryption'  =>  :'RC4_128',           :'bits'  =>  128,  :'mac'  =>  :'MD5',        :'id'  =>  [0x00, 0x18]},
    {:'name'  =>  :'TLS_DH_Anon_EXPORT_WITH_DES40_CBC_SHA',    :'keyexchange'  =>  :'DH',                  :'authentication'  =>  :'Anon',                :'encryption'  =>  :'DES40_CBC',         :'bits'  =>  40,   :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x19]},
    {:'name'  =>  :'TLS_DH_Anon_WITH_DES_CBC_SHA',             :'keyexchange'  =>  :'DH',                  :'authentication'  =>  :'Anon',                :'encryption'  =>  :'DES_CBC',           :'bits'  =>  56,   :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x1A]},
    {:'name'  =>  :'TLS_DH_Anon_WITH_3DES_EDE_CBC_SHA',        :'keyexchange'  =>  :'DH',                  :'authentication'  =>  :'Anon',                :'encryption'  =>  :'3DES_EDE_CBC',      :'bits'  =>  168,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x1B]},
    {:'name'  =>  :'SSL_FORTEZZA_KEA_WITH_NULL_SHA',           :'keyexchange'  =>  :'FORTEZZA',            :'authentication'  =>  :'KEA',                 :'encryption'  =>  :'NULL',              :'bits'  =>  0,    :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x1C]},
    {:'name'  =>  :'SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA',   :'keyexchange'  =>  :'FORTEZZA',            :'authentication'  =>  :'KEA',                 :'encryption'  =>  :'FORTEZZA_CBC',      :'bits'  =>  80,   :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x1D]},
    {:'name'  =>  :'TLS_KRB5_WITH_DES_CBC_SHA',                :'keyexchange'  =>  :'KRB5',                :'authentication'  =>  :'KRB5',                :'encryption'  =>  :'DES_CBC',           :'bits'  =>  56,   :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x1E]},
    {:'name'  =>  :'TLS_KRB5_WITH_3DES_EDE_CBC_SHA',           :'keyexchange'  =>  :'KRB5',                :'authentication'  =>  :'KRB5',                :'encryption'  =>  :'3DES_EDE_CBC',      :'bits'  =>  168,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x1F]},
    {:'name'  =>  :'TLS_KRB5_WITH_RC4_128_SHA',                :'keyexchange'  =>  :'KRB5',                :'authentication'  =>  :'KRB5',                :'encryption'  =>  :'RC4_128',           :'bits'  =>  128,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x20]},
    {:'name'  =>  :'TLS_KRB5_WITH_IDEA_CBC_SHA',               :'keyexchange'  =>  :'KRB5',                :'authentication'  =>  :'KRB5',                :'encryption'  =>  :'IDEA_CBC',          :'bits'  =>  128,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x21]},
    {:'name'  =>  :'TLS_KRB5_WITH_DES_CBC_MD5',                :'keyexchange'  =>  :'KRB5',                :'authentication'  =>  :'KRB5',                :'encryption'  =>  :'DES_CBC',           :'bits'  =>  56,   :'mac'  =>  :'MD5',        :'id'  =>  [0x00, 0x22]},
    {:'name'  =>  :'TLS_KRB5_WITH_3DES_EDE_CBC_MD5',           :'keyexchange'  =>  :'KRB5',                :'authentication'  =>  :'KRB5',                :'encryption'  =>  :'3DES_EDE_CBC',      :'bits'  =>  168,  :'mac'  =>  :'MD5',        :'id'  =>  [0x00, 0x23]},
    {:'name'  =>  :'TLS_KRB5_WITH_RC4_128_MD5',                :'keyexchange'  =>  :'KRB5',                :'authentication'  =>  :'KRB5',                :'encryption'  =>  :'RC4_128',           :'bits'  =>  128,  :'mac'  =>  :'MD5',        :'id'  =>  [0x00, 0x24]},
    {:'name'  =>  :'TLS_KRB5_WITH_IDEA_CBC_MD5',               :'keyexchange'  =>  :'KRB5',                :'authentication'  =>  :'KRB5',                :'encryption'  =>  :'IDEA_CBC',          :'bits'  =>  128,  :'mac'  =>  :'MD5',        :'id'  =>  [0x00, 0x25]},
    {:'name'  =>  :'TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA',      :'keyexchange'  =>  :'KRB5_EXPORT',         :'authentication'  =>  :'KRB5_EXPORT',         :'encryption'  =>  :'DES_CBC_40',        :'bits'  =>  40,   :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x26]},
    {:'name'  =>  :'TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA',      :'keyexchange'  =>  :'KRB5_EXPORT',         :'authentication'  =>  :'KRB5_EXPORT',         :'encryption'  =>  :'RC2_CBC_40',        :'bits'  =>  40,   :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x27]},
    {:'name'  =>  :'TLS_KRB5_EXPORT_WITH_RC4_40_SHA',          :'keyexchange'  =>  :'KRB5_EXPORT',         :'authentication'  =>  :'KRB5_EXPORT',         :'encryption'  =>  :'RC4_40',            :'bits'  =>  40,   :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x28]},
    {:'name'  =>  :'TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5',      :'keyexchange'  =>  :'KRB5_EXPORT',         :'authentication'  =>  :'KRB5_EXPORT',         :'encryption'  =>  :'DES_CBC_40',        :'bits'  =>  40,   :'mac'  =>  :'MD5',        :'id'  =>  [0x00, 0x29]},
    {:'name'  =>  :'TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5',      :'keyexchange'  =>  :'KRB5_EXPORT',         :'authentication'  =>  :'KRB5_EXPORT',         :'encryption'  =>  :'RC2_CBC_40',        :'bits'  =>  40,   :'mac'  =>  :'MD5',        :'id'  =>  [0x00, 0x2A]},
    {:'name'  =>  :'TLS_KRB5_EXPORT_WITH_RC4_40_MD5',          :'keyexchange'  =>  :'KRB5_EXPORT',         :'authentication'  =>  :'KRB5_EXPORT',         :'encryption'  =>  :'RC4_40',            :'bits'  =>  40,   :'mac'  =>  :'MD5',        :'id'  =>  [0x00, 0x2B]},
    {:'name'  =>  :'TLS_PSK_WITH_NULL_SHA',                    :'keyexchange'  =>  :'PSK',                 :'authentication'  =>  :'PSK',                 :'encryption'  =>  :'NULL',              :'bits'  =>  0,    :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x2C]},
    {:'name'  =>  :'TLS_DHE_PSK_WITH_NULL_SHA',                :'keyexchange'  =>  :'DHE',                 :'authentication'  =>  :'PSK',                 :'encryption'  =>  :'NULL',              :'bits'  =>  0,    :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x2D]},
    {:'name'  =>  :'TLS_RSA_PSK_WITH_NULL_SHA',                :'keyexchange'  =>  :'RSA',                 :'authentication'  =>  :'PSK',                 :'encryption'  =>  :'NULL',              :'bits'  =>  0,    :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x2E]},
    {:'name'  =>  :'TLS_RSA_WITH_AES_128_CBC_SHA',             :'keyexchange'  =>  :'RSA',                 :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'AES_128_CBC',       :'bits'  =>  128,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x2F]},
    {:'name'  =>  :'TLS_DH_DSS_WITH_AES_128_CBC_SHA',          :'keyexchange'  =>  :'DH',                  :'authentication'  =>  :'DSS',                 :'encryption'  =>  :'AES_128_CBC',       :'bits'  =>  128,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x30]},
    {:'name'  =>  :'TLS_DH_RSA_WITH_AES_128_CBC_SHA',          :'keyexchange'  =>  :'DH',                  :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'AES_128_CBC',       :'bits'  =>  128,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x31]},
    {:'name'  =>  :'TLS_DHE_DSS_WITH_AES_128_CBC_SHA',         :'keyexchange'  =>  :'DHE',                 :'authentication'  =>  :'DSS',                 :'encryption'  =>  :'AES_128_CBC',       :'bits'  =>  128,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x32]},
    {:'name'  =>  :'TLS_DHE_RSA_WITH_AES_128_CBC_SHA',         :'keyexchange'  =>  :'DHE',                 :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'AES_128_CBC',       :'bits'  =>  128,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x33]},
    {:'name'  =>  :'TLS_DH_Anon_WITH_AES_128_CBC_SHA',         :'keyexchange'  =>  :'DH',                  :'authentication'  =>  :'Anon',                :'encryption'  =>  :'AES_128_CBC',       :'bits'  =>  128,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x34]},
    {:'name'  =>  :'TLS_RSA_WITH_AES_256_CBC_SHA',             :'keyexchange'  =>  :'RSA',                 :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'AES_256_CBC',       :'bits'  =>  256,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x35]},
    {:'name'  =>  :'TLS_DH_DSS_WITH_AES_256_CBC_SHA',          :'keyexchange'  =>  :'DH',                  :'authentication'  =>  :'DSS',                 :'encryption'  =>  :'AES_256_CBC',       :'bits'  =>  256,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x36]},
    {:'name'  =>  :'TLS_DH_RSA_WITH_AES_256_CBC_SHA',          :'keyexchange'  =>  :'DH',                  :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'AES_256_CBC',       :'bits'  =>  256,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x37]},
    {:'name'  =>  :'TLS_DHE_DSS_WITH_AES_256_CBC_SHA',         :'keyexchange'  =>  :'DHE',                 :'authentication'  =>  :'DSS',                 :'encryption'  =>  :'AES_256_CBC',       :'bits'  =>  256,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x38]},
    {:'name'  =>  :'TLS_DHE_RSA_WITH_AES_256_CBC_SHA',         :'keyexchange'  =>  :'DHE',                 :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'AES_256_CBC',       :'bits'  =>  256,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x39]},
    {:'name'  =>  :'TLS_DH_Anon_WITH_AES_256_CBC_SHA',         :'keyexchange'  =>  :'DH',                  :'authentication'  =>  :'Anon',                :'encryption'  =>  :'AES_256_CBC',       :'bits'  =>  256,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x3A]},
    {:'name'  =>  :'TLS_RSA_WITH_NULL_SHA256',                 :'keyexchange'  =>  :'RSA',                 :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'NULL',              :'bits'  =>  0,    :'mac'  =>  :'SHA256',     :'id'  =>  [0x00, 0x3B]},
    {:'name'  =>  :'TLS_RSA_WITH_AES_128_CBC_SHA256',          :'keyexchange'  =>  :'RSA',                 :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'AES_128_CBC',       :'bits'  =>  128,  :'mac'  =>  :'SHA256',     :'id'  =>  [0x00, 0x3C]},
    {:'name'  =>  :'TLS_RSA_WITH_AES_256_CBC_SHA256',          :'keyexchange'  =>  :'RSA',                 :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'AES_256_CBC',       :'bits'  =>  256,  :'mac'  =>  :'SHA256',     :'id'  =>  [0x00, 0x3D]},
    {:'name'  =>  :'TLS_DH_DSS_WITH_AES_128_CBC_SHA256',       :'keyexchange'  =>  :'DH',                  :'authentication'  =>  :'DSS',                 :'encryption'  =>  :'AES_128_CBC',       :'bits'  =>  128,  :'mac'  =>  :'SHA256',     :'id'  =>  [0x00, 0x3E]},
    {:'name'  =>  :'TLS_DH_RSA_WITH_AES_128_CBC_SHA256',       :'keyexchange'  =>  :'DH',                  :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'AES_128_CBC',       :'bits'  =>  128,  :'mac'  =>  :'SHA256',     :'id'  =>  [0x00, 0x3F]},
    {:'name'  =>  :'TLS_DHE_DSS_WITH_AES_128_CBC_SHA256',      :'keyexchange'  =>  :'DHE',                 :'authentication'  =>  :'DSS',                 :'encryption'  =>  :'AES_128_CBC',       :'bits'  =>  128,  :'mac'  =>  :'SHA256',     :'id'  =>  [0x00, 0x40]},
    {:'name'  =>  :'TLS_RSA_WITH_CAMELLIA_128_CBC_SHA',        :'keyexchange'  =>  :'RSA',                 :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'CAMELLIA_128_CBC',  :'bits'  =>  128,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x41]},
    {:'name'  =>  :'TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA',     :'keyexchange'  =>  :'DH',                  :'authentication'  =>  :'DSS',                 :'encryption'  =>  :'CAMELLIA_128_CBC',  :'bits'  =>  128,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x42]},
    {:'name'  =>  :'TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA',     :'keyexchange'  =>  :'DH',                  :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'CAMELLIA_128_CBC',  :'bits'  =>  128,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x43]},
    {:'name'  =>  :'TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA',    :'keyexchange'  =>  :'DHE',                 :'authentication'  =>  :'DSS',                 :'encryption'  =>  :'CAMELLIA_128_CBC',  :'bits'  =>  128,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x44]},
    {:'name'  =>  :'TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA',    :'keyexchange'  =>  :'DHE',                 :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'CAMELLIA_128_CBC',  :'bits'  =>  128,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x45]},
    {:'name'  =>  :'TLS_DH_Anon_WITH_CAMELLIA_128_CBC_SHA',    :'keyexchange'  =>  :'DH',                  :'authentication'  =>  :'Anon',                :'encryption'  =>  :'CAMELLIA_128_CBC',  :'bits'  =>  128,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x46]},
    {:'name'  =>  :'TLS_ECDH_ECDSA_WITH_NULL_SHA',             :'keyexchange'  =>  :'ECDH',                :'authentication'  =>  :'ECDSA',               :'encryption'  =>  :'NULL',              :'bits'  =>  0,    :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x47]},
    {:'name'  =>  :'TLS_ECDH_ECDSA_WITH_RC4_128_SHA',          :'keyexchange'  =>  :'ECDH',                :'authentication'  =>  :'ECDSA',               :'encryption'  =>  :'RC4_128',           :'bits'  =>  128,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x48]},
    {:'name'  =>  :'TLS_ECDH_ECDSA_WITH_DES_CBC_SHA',          :'keyexchange'  =>  :'ECDH',                :'authentication'  =>  :'ECDSA',               :'encryption'  =>  :'DES_CBC',           :'bits'  =>  56,   :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x49]},
    {:'name'  =>  :'TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA',     :'keyexchange'  =>  :'ECDH',                :'authentication'  =>  :'ECDSA',               :'encryption'  =>  :'3DES_EDE_CBC',      :'bits'  =>  168,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x4A]},
    {:'name'  =>  :'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA',      :'keyexchange'  =>  :'ECDH',                :'authentication'  =>  :'ECDSA',               :'encryption'  =>  :'AES_128_CBC',       :'bits'  =>  128,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x4B]},
    {:'name'  =>  :'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA',      :'keyexchange'  =>  :'ECDH',                :'authentication'  =>  :'ECDSA',               :'encryption'  =>  :'AES_256_CBC',       :'bits'  =>  256,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x4C]},
    {:'name'  =>  :'TLS_RSA_EXPORT1024_WITH_RC4_56_MD5',       :'keyexchange'  =>  :'RSA_EXPORT1024',      :'authentication'  =>  :'RSA_EXPORT1024',      :'encryption'  =>  :'RC4_56',            :'bits'  =>  56,   :'mac'  =>  :'MD5',        :'id'  =>  [0x00, 0x60]},
    {:'name'  =>  :'TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5',   :'keyexchange'  =>  :'RSA_EXPORT1024',      :'authentication'  =>  :'RSA_EXPORT1024',      :'encryption'  =>  :'RC2_CBC_56',        :'bits'  =>  56,   :'mac'  =>  :'MD5',        :'id'  =>  [0x00, 0x61]},
    {:'name'  =>  :'TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA',      :'keyexchange'  =>  :'RSA_EXPORT1024',      :'authentication'  =>  :'RSA_EXPORT1024',      :'encryption'  =>  :'DES_CBC',           :'bits'  =>  56,   :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x62]},
    {:'name'  =>  :'TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA',  :'keyexchange'  =>  :'DHE',                 :'authentication'  =>  :'DSS',                 :'encryption'  =>  :'DES_CBC',           :'bits'  =>  56,   :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x63]},
    {:'name'  =>  :'TLS_RSA_EXPORT1024_WITH_RC4_56_SHA',       :'keyexchange'  =>  :'RSA_EXPORT1024',      :'authentication'  =>  :'RSA_EXPORT1024',      :'encryption'  =>  :'RC4_56',            :'bits'  =>  56,   :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x64]},
    {:'name'  =>  :'TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA',   :'keyexchange'  =>  :'DHE',                 :'authentication'  =>  :'DSS',                 :'encryption'  =>  :'RC4_56',            :'bits'  =>  56,   :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x65]},
    {:'name'  =>  :'TLS_DHE_DSS_WITH_RC4_128_SHA',             :'keyexchange'  =>  :'DHE',                 :'authentication'  =>  :'DSS',                 :'encryption'  =>  :'RC4_128',           :'bits'  =>  128,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x66]},
    {:'name'  =>  :'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256',      :'keyexchange'  =>  :'DHE',                 :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'AES_128_CBC',       :'bits'  =>  128,  :'mac'  =>  :'SHA256',     :'id'  =>  [0x00, 0x67]},
    {:'name'  =>  :'TLS_DH_DSS_WITH_AES_256_CBC_SHA256',       :'keyexchange'  =>  :'DH',                  :'authentication'  =>  :'DSS',                 :'encryption'  =>  :'AES_256_CBC',       :'bits'  =>  256,  :'mac'  =>  :'SHA256',     :'id'  =>  [0x00, 0x68]},
    {:'name'  =>  :'TLS_DH_RSA_WITH_AES_256_CBC_SHA256',       :'keyexchange'  =>  :'DH',                  :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'AES_256_CBC',       :'bits'  =>  256,  :'mac'  =>  :'SHA256',     :'id'  =>  [0x00, 0x69]},
    {:'name'  =>  :'TLS_DHE_DSS_WITH_AES_256_CBC_SHA256',      :'keyexchange'  =>  :'DHE',                 :'authentication'  =>  :'DSS',                 :'encryption'  =>  :'AES_256_CBC',       :'bits'  =>  256,  :'mac'  =>  :'SHA256',     :'id'  =>  [0x00, 0x6A]},
    {:'name'  =>  :'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256',      :'keyexchange'  =>  :'DHE',                 :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'AES_256_CBC',       :'bits'  =>  256,  :'mac'  =>  :'SHA256',     :'id'  =>  [0x00, 0x6B]},
    {:'name'  =>  :'TLS_DH_Anon_WITH_AES_128_CBC_SHA256',      :'keyexchange'  =>  :'DH',                  :'authentication'  =>  :'Anon',                :'encryption'  =>  :'AES_128_CBC',       :'bits'  =>  128,  :'mac'  =>  :'SHA256',     :'id'  =>  [0x00, 0x6C]},
    {:'name'  =>  :'TLS_DH_Anon_WITH_AES_256_CBC_SHA256',      :'keyexchange'  =>  :'DH',                  :'authentication'  =>  :'Anon',                :'encryption'  =>  :'AES_256_CBC',       :'bits'  =>  256,  :'mac'  =>  :'SHA256',     :'id'  =>  [0x00, 0x6D]},
    {:'name'  =>  :'TLS_GOSTR341094_WITH_28147_CNT_IMIT',      :'keyexchange'  =>  :'VKOGOSTR34.10-94',    :'authentication'  =>  :'VKOGOSTR34.10-94',    :'encryption'  =>  :'GOST28147',         :'bits'  =>  256,  :'mac'  =>  :'GOST28147',  :'id'  =>  [0x00, 0x80]},
    {:'name'  =>  :'TLS_GOSTR341001_WITH_28147_CNT_IMIT',      :'keyexchange'  =>  :'VKOGOSTR34.10-2001',  :'authentication'  =>  :'VKOGOSTR34.10-2001',  :'encryption'  =>  :'GOST28147',         :'bits'  =>  256,  :'mac'  =>  :'GOST28147',  :'id'  =>  [0x00, 0x81]},
    {:'name'  =>  :'TLS_GOSTR341094_WITH_NULL_GOSTR3411',      :'keyexchange'  =>  :'VKOGOSTR34.10-94',    :'authentication'  =>  :'VKOGOSTR34.10-94',    :'encryption'  =>  :'NULL',              :'bits'  =>  0,    :'mac'  =>  :'GOSTR3411',  :'id'  =>  [0x00, 0x82]},
    {:'name'  =>  :'TLS_GOSTR341001_WITH_NULL_GOSTR3411',      :'keyexchange'  =>  :'VKOGOSTR34.10-2001',  :'authentication'  =>  :'VKOGOSTR34.10-2001',  :'encryption'  =>  :'NULL',              :'bits'  =>  0,    :'mac'  =>  :'GOSTR3411',  :'id'  =>  [0x00, 0x83]},
    {:'name'  =>  :'TLS_RSA_WITH_CAMELLIA_256_CBC_SHA',        :'keyexchange'  =>  :'RSA',                 :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'CAMELLIA_256_CBC',  :'bits'  =>  256,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x84]},
    {:'name'  =>  :'TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA',     :'keyexchange'  =>  :'DH',                  :'authentication'  =>  :'DSS',                 :'encryption'  =>  :'CAMELLIA_256_CBC',  :'bits'  =>  256,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x85]},
    {:'name'  =>  :'TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA',     :'keyexchange'  =>  :'DH',                  :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'CAMELLIA_256_CBC',  :'bits'  =>  256,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x86]},
    {:'name'  =>  :'TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA',    :'keyexchange'  =>  :'DHE',                 :'authentication'  =>  :'DSS',                 :'encryption'  =>  :'CAMELLIA_256_CBC',  :'bits'  =>  256,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x87]},
    {:'name'  =>  :'TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA',    :'keyexchange'  =>  :'DHE',                 :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'CAMELLIA_256_CBC',  :'bits'  =>  256,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x88]},
    {:'name'  =>  :'TLS_DH_Anon_WITH_CAMELLIA_256_CBC_SHA',    :'keyexchange'  =>  :'DH',                  :'authentication'  =>  :'Anon',                :'encryption'  =>  :'CAMELLIA_256_CBC',  :'bits'  =>  256,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x89]},
    {:'name'  =>  :'TLS_PSK_WITH_RC4_128_SHA',                 :'keyexchange'  =>  :'PSK',                 :'authentication'  =>  :'PSK',                 :'encryption'  =>  :'RC4_128',           :'bits'  =>  128,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x8A]},
    {:'name'  =>  :'TLS_PSK_WITH_3DES_EDE_CBC_SHA',            :'keyexchange'  =>  :'PSK',                 :'authentication'  =>  :'PSK',                 :'encryption'  =>  :'3DES_EDE_CBC',      :'bits'  =>  168,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x8B]},
    {:'name'  =>  :'TLS_PSK_WITH_AES_128_CBC_SHA',             :'keyexchange'  =>  :'PSK',                 :'authentication'  =>  :'PSK',                 :'encryption'  =>  :'AES_128_CBC',       :'bits'  =>  128,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x8C]},
    {:'name'  =>  :'TLS_PSK_WITH_AES_256_CBC_SHA',             :'keyexchange'  =>  :'PSK',                 :'authentication'  =>  :'PSK',                 :'encryption'  =>  :'AES_256_CBC',       :'bits'  =>  256,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x8D]},
    {:'name'  =>  :'TLS_DHE_PSK_WITH_RC4_128_SHA',             :'keyexchange'  =>  :'DHE',                 :'authentication'  =>  :'PSK',                 :'encryption'  =>  :'RC4_128',           :'bits'  =>  128,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x8E]},
    {:'name'  =>  :'TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA',        :'keyexchange'  =>  :'DHE',                 :'authentication'  =>  :'PSK',                 :'encryption'  =>  :'3DES_EDE_CBC',      :'bits'  =>  168,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x8F]},
    {:'name'  =>  :'TLS_DHE_PSK_WITH_AES_128_CBC_SHA',         :'keyexchange'  =>  :'DHE',                 :'authentication'  =>  :'PSK',                 :'encryption'  =>  :'AES_128_CBC',       :'bits'  =>  128,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x90]},
    {:'name'  =>  :'TLS_DHE_PSK_WITH_AES_256_CBC_SHA',         :'keyexchange'  =>  :'DHE',                 :'authentication'  =>  :'PSK',                 :'encryption'  =>  :'AES_256_CBC',       :'bits'  =>  256,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x91]},
    {:'name'  =>  :'TLS_RSA_PSK_WITH_RC4_128_SHA',             :'keyexchange'  =>  :'RSA',                 :'authentication'  =>  :'PSK',                 :'encryption'  =>  :'RC4_128',           :'bits'  =>  128,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x92]},
    {:'name'  =>  :'TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA',        :'keyexchange'  =>  :'RSA',                 :'authentication'  =>  :'PSK',                 :'encryption'  =>  :'3DES_EDE_CBC',      :'bits'  =>  168,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x93]},
    {:'name'  =>  :'TLS_RSA_PSK_WITH_AES_128_CBC_SHA',         :'keyexchange'  =>  :'RSA',                 :'authentication'  =>  :'PSK',                 :'encryption'  =>  :'AES_128_CBC',       :'bits'  =>  128,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x94]},
    {:'name'  =>  :'TLS_RSA_PSK_WITH_AES_256_CBC_SHA',         :'keyexchange'  =>  :'RSA',                 :'authentication'  =>  :'PSK',                 :'encryption'  =>  :'AES_256_CBC',       :'bits'  =>  256,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x95]},
    {:'name'  =>  :'TLS_RSA_WITH_SEED_CBC_SHA',                :'keyexchange'  =>  :'RSA',                 :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'SEED_CBC',          :'bits'  =>  128,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x96]},
    {:'name'  =>  :'TLS_DH_DSS_WITH_SEED_CBC_SHA',             :'keyexchange'  =>  :'DH',                  :'authentication'  =>  :'DSS',                 :'encryption'  =>  :'SEED_CBC',          :'bits'  =>  128,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x97]},
    {:'name'  =>  :'TLS_DH_RSA_WITH_SEED_CBC_SHA',             :'keyexchange'  =>  :'DH',                  :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'SEED_CBC',          :'bits'  =>  128,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x98]},
    {:'name'  =>  :'TLS_DHE_DSS_WITH_SEED_CBC_SHA',            :'keyexchange'  =>  :'DHE',                 :'authentication'  =>  :'DSS',                 :'encryption'  =>  :'SEED_CBC',          :'bits'  =>  128,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x99]},
    {:'name'  =>  :'TLS_DHE_RSA_WITH_SEED_CBC_SHA',            :'keyexchange'  =>  :'DHE',                 :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'SEED_CBC',          :'bits'  =>  128,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x9A]},
    {:'name'  =>  :'TLS_DH_Anon_WITH_SEED_CBC_SHA',            :'keyexchange'  =>  :'DH',                  :'authentication'  =>  :'Anon',                :'encryption'  =>  :'SEED_CBC',          :'bits'  =>  128,  :'mac'  =>  :'SHA',        :'id'  =>  [0x00, 0x9B]},
    {:'name'  =>  :'TLS_RSA_WITH_AES_128_GCM_SHA256',          :'keyexchange'  =>  :'RSA',                 :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'AES_128_GCM',       :'bits'  =>  128,  :'mac'  =>  :'SHA256',     :'id'  =>  [0x00, 0x9C]},
    {:'name'  =>  :'TLS_RSA_WITH_AES_256_GCM_SHA384',          :'keyexchange'  =>  :'RSA',                 :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'AES_256_GCM',       :'bits'  =>  256,  :'mac'  =>  :'SHA384',     :'id'  =>  [0x00, 0x9D]},
    {:'name'  =>  :'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256',      :'keyexchange'  =>  :'DHE',                 :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'AES_128_GCM',       :'bits'  =>  128,  :'mac'  =>  :'SHA256',     :'id'  =>  [0x00, 0x9E]},
    {:'name'  =>  :'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',      :'keyexchange'  =>  :'DHE',                 :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'AES_256_GCM',       :'bits'  =>  256,  :'mac'  =>  :'SHA384',     :'id'  =>  [0x00, 0x9F]},
    {:'name'  =>  :'TLS_DH_RSA_WITH_AES_128_GCM_SHA256',       :'keyexchange'  =>  :'DH',                  :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'AES_128_GCM',       :'bits'  =>  128,  :'mac'  =>  :'SHA256',     :'id'  =>  [0x00, 0xA0]},
    {:'name'  =>  :'TLS_DH_RSA_WITH_AES_256_GCM_SHA384',       :'keyexchange'  =>  :'DH',                  :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'AES_256_GCM',       :'bits'  =>  256,  :'mac'  =>  :'SHA384',     :'id'  =>  [0x00, 0xA1]},
    {:'name'  =>  :'TLS_DHE_DSS_WITH_AES_128_GCM_SHA256',      :'keyexchange'  =>  :'DHE',                 :'authentication'  =>  :'DSS',                 :'encryption'  =>  :'AES_128_GCM',       :'bits'  =>  128,  :'mac'  =>  :'SHA256',     :'id'  =>  [0x00, 0xA2]},
    {:'name'  =>  :'TLS_DHE_DSS_WITH_AES_256_GCM_SHA384',      :'keyexchange'  =>  :'DHE',                 :'authentication'  =>  :'DSS',                 :'encryption'  =>  :'AES_256_GCM',       :'bits'  =>  256,  :'mac'  =>  :'SHA384',     :'id'  =>  [0x00, 0xA3]},
    {:'name'  =>  :'TLS_DH_DSS_WITH_AES_128_GCM_SHA256',       :'keyexchange'  =>  :'DH',                  :'authentication'  =>  :'DSS',                 :'encryption'  =>  :'AES_128_GCM',       :'bits'  =>  128,  :'mac'  =>  :'SHA256',     :'id'  =>  [0x00, 0xA4]},
    {:'name'  =>  :'TLS_DH_DSS_WITH_AES_256_GCM_SHA384',       :'keyexchange'  =>  :'DH',                  :'authentication'  =>  :'DSS',                 :'encryption'  =>  :'AES_256_GCM',       :'bits'  =>  256,  :'mac'  =>  :'SHA384',     :'id'  =>  [0x00, 0xA5]},
    {:'name'  =>  :'TLS_DH_Anon_WITH_AES_128_GCM_SHA256',      :'keyexchange'  =>  :'DH',                  :'authentication'  =>  :'Anon',                :'encryption'  =>  :'AES_128_GCM',       :'bits'  =>  128,  :'mac'  =>  :'SHA256',     :'id'  =>  [0x00, 0xA6]},
    {:'name'  =>  :'TLS_DH_Anon_WITH_AES_256_GCM_SHA384',      :'keyexchange'  =>  :'DH',                  :'authentication'  =>  :'Anon',                :'encryption'  =>  :'AES_256_GCM',       :'bits'  =>  256,  :'mac'  =>  :'SHA384',     :'id'  =>  [0x00, 0xA7]},
    {:'name'  =>  :'TLS_PSK_WITH_AES_128_GCM_SHA256',          :'keyexchange'  =>  :'PSK',                 :'authentication'  =>  :'PSK',                 :'encryption'  =>  :'AES_128_GCM',       :'bits'  =>  128,  :'mac'  =>  :'SHA256',     :'id'  =>  [0x00, 0xA8]},
    {:'name'  =>  :'TLS_PSK_WITH_AES_256_GCM_SHA384',          :'keyexchange'  =>  :'PSK',                 :'authentication'  =>  :'PSK',                 :'encryption'  =>  :'AES_256_GCM',       :'bits'  =>  256,  :'mac'  =>  :'SHA384',     :'id'  =>  [0x00, 0xA9]},
    {:'name'  =>  :'TLS_DHE_PSK_WITH_AES_128_GCM_SHA256',      :'keyexchange'  =>  :'DHE',                 :'authentication'  =>  :'PSK',                 :'encryption'  =>  :'AES_128_GCM',       :'bits'  =>  128,  :'mac'  =>  :'SHA256',     :'id'  =>  [0x00, 0xAA]},
    {:'name'  =>  :'TLS_DHE_PSK_WITH_AES_256_GCM_SHA384',      :'keyexchange'  =>  :'DHE',                 :'authentication'  =>  :'PSK',                 :'encryption'  =>  :'AES_256_GCM',       :'bits'  =>  256,  :'mac'  =>  :'SHA384',     :'id'  =>  [0x00, 0xAB]},
    {:'name'  =>  :'TLS_RSA_PSK_WITH_AES_128_GCM_SHA256',      :'keyexchange'  =>  :'RSA',                 :'authentication'  =>  :'PSK',                 :'encryption'  =>  :'AES_128_GCM',       :'bits'  =>  128,  :'mac'  =>  :'SHA256',     :'id'  =>  [0x00, 0xAC]},
    {:'name'  =>  :'TLS_RSA_PSK_WITH_AES_256_GCM_SHA384',      :'keyexchange'  =>  :'RSA',                 :'authentication'  =>  :'PSK',                 :'encryption'  =>  :'AES_256_GCM',       :'bits'  =>  256,  :'mac'  =>  :'SHA384',     :'id'  =>  [0x00, 0xAD]},
    {:'name'  =>  :'TLS_PSK_WITH_AES_128_CBC_SHA256',          :'keyexchange'  =>  :'PSK',                 :'authentication'  =>  :'PSK',                 :'encryption'  =>  :'AES_128_CBC',       :'bits'  =>  128,  :'mac'  =>  :'SHA256',     :'id'  =>  [0x00, 0xAE]},
    {:'name'  =>  :'TLS_PSK_WITH_AES_256_CBC_SHA384',          :'keyexchange'  =>  :'PSK',                 :'authentication'  =>  :'PSK',                 :'encryption'  =>  :'AES_256_CBC',       :'bits'  =>  256,  :'mac'  =>  :'SHA384',     :'id'  =>  [0x00, 0xAF]},
    {:'name'  =>  :'TLS_PSK_WITH_NULL_SHA256',                 :'keyexchange'  =>  :'PSK',                 :'authentication'  =>  :'PSK',                 :'encryption'  =>  :'NULL',              :'bits'  =>  0,    :'mac'  =>  :'SHA256',     :'id'  =>  [0x00, 0xB0]},
    {:'name'  =>  :'TLS_PSK_WITH_NULL_SHA384',                 :'keyexchange'  =>  :'PSK',                 :'authentication'  =>  :'PSK',                 :'encryption'  =>  :'NULL',              :'bits'  =>  0,    :'mac'  =>  :'SHA384',     :'id'  =>  [0x00, 0xB1]},
    {:'name'  =>  :'TLS_DHE_PSK_WITH_AES_128_CBC_SHA256',      :'keyexchange'  =>  :'DHE',                 :'authentication'  =>  :'PSK',                 :'encryption'  =>  :'AES_128_CBC',       :'bits'  =>  128,  :'mac'  =>  :'SHA256',     :'id'  =>  [0x00, 0xB2]},
    {:'name'  =>  :'TLS_DHE_PSK_WITH_AES_256_CBC_SHA384',      :'keyexchange'  =>  :'DHE',                 :'authentication'  =>  :'PSK',                 :'encryption'  =>  :'AES_256_CBC',       :'bits'  =>  256,  :'mac'  =>  :'SHA384',     :'id'  =>  [0x00, 0xB3]},
    {:'name'  =>  :'TLS_DHE_PSK_WITH_NULL_SHA256',             :'keyexchange'  =>  :'DHE',                 :'authentication'  =>  :'PSK',                 :'encryption'  =>  :'NULL',              :'bits'  =>  0,    :'mac'  =>  :'SHA256',     :'id'  =>  [0x00, 0xB4]},
    {:'name'  =>  :'TLS_DHE_PSK_WITH_NULL_SHA384',             :'keyexchange'  =>  :'DHE',                 :'authentication'  =>  :'PSK',                 :'encryption'  =>  :'NULL',              :'bits'  =>  0,    :'mac'  =>  :'SHA384',     :'id'  =>  [0x00, 0xB5]},
    {:'name'  =>  :'TLS_RSA_PSK_WITH_AES_128_CBC_SHA256',      :'keyexchange'  =>  :'RSA',                 :'authentication'  =>  :'PSK',                 :'encryption'  =>  :'AES_128_CBC',       :'bits'  =>  128,  :'mac'  =>  :'SHA256',     :'id'  =>  [0x00, 0xB6]},
    {:'name'  =>  :'TLS_RSA_PSK_WITH_AES_256_CBC_SHA384',      :'keyexchange'  =>  :'RSA',                 :'authentication'  =>  :'PSK',                 :'encryption'  =>  :'AES_256_CBC',       :'bits'  =>  256,  :'mac'  =>  :'SHA384',     :'id'  =>  [0x00, 0xB7]},
    {:'name'  =>  :'TLS_RSA_PSK_WITH_NULL_SHA256',             :'keyexchange'  =>  :'RSA',                 :'authentication'  =>  :'PSK',                 :'encryption'  =>  :'NULL',              :'bits'  =>  0,    :'mac'  =>  :'SHA256',     :'id'  =>  [0x00, 0xB8]},
    {:'name'  =>  :'TLS_RSA_PSK_WITH_NULL_SHA384',             :'keyexchange'  =>  :'RSA',                 :'authentication'  =>  :'PSK',                 :'encryption'  =>  :'NULL',              :'bits'  =>  0,    :'mac'  =>  :'SHA384',     :'id'  =>  [0x00, 0xB9]},
    {:'name'  =>  :'TLS_ECDH_ECDSA_WITH_NULL_SHA',             :'keyexchange'  =>  :'ECDH',                :'authentication'  =>  :'ECDSA',               :'encryption'  =>  :'NULL',              :'bits'  =>  0,    :'mac'  =>  :'SHA',        :'id'  =>  [0xC0, 0x01]},
    {:'name'  =>  :'TLS_ECDH_ECDSA_WITH_RC4_128_SHA',          :'keyexchange'  =>  :'ECDH',                :'authentication'  =>  :'ECDSA',               :'encryption'  =>  :'RC4_128',           :'bits'  =>  128,  :'mac'  =>  :'SHA',        :'id'  =>  [0xC0, 0x02]},
    {:'name'  =>  :'TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA',     :'keyexchange'  =>  :'ECDH',                :'authentication'  =>  :'ECDSA',               :'encryption'  =>  :'3DES_EDE_CBC',      :'bits'  =>  168,  :'mac'  =>  :'SHA',        :'id'  =>  [0xC0, 0x03]},
    {:'name'  =>  :'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA',      :'keyexchange'  =>  :'ECDH',                :'authentication'  =>  :'ECDSA',               :'encryption'  =>  :'AES_128_CBC',       :'bits'  =>  128,  :'mac'  =>  :'SHA',        :'id'  =>  [0xC0, 0x04]},
    {:'name'  =>  :'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA',      :'keyexchange'  =>  :'ECDH',                :'authentication'  =>  :'ECDSA',               :'encryption'  =>  :'AES_256_CBC',       :'bits'  =>  256,  :'mac'  =>  :'SHA',        :'id'  =>  [0xC0, 0x05]},
    {:'name'  =>  :'TLS_ECDHE_ECDSA_WITH_NULL_SHA',            :'keyexchange'  =>  :'ECDHE',               :'authentication'  =>  :'ECDSA',               :'encryption'  =>  :'NULL',              :'bits'  =>  0,    :'mac'  =>  :'SHA',        :'id'  =>  [0xC0, 0x06]},
    {:'name'  =>  :'TLS_ECDHE_ECDSA_WITH_RC4_128_SHA',         :'keyexchange'  =>  :'ECDHE',               :'authentication'  =>  :'ECDSA',               :'encryption'  =>  :'RC4_128',           :'bits'  =>  128,  :'mac'  =>  :'SHA',        :'id'  =>  [0xC0, 0x07]},
    {:'name'  =>  :'TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA',    :'keyexchange'  =>  :'ECDHE',               :'authentication'  =>  :'ECDSA',               :'encryption'  =>  :'3DES_EDE_CBC',      :'bits'  =>  168,  :'mac'  =>  :'SHA',        :'id'  =>  [0xC0, 0x08]},
    {:'name'  =>  :'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA',     :'keyexchange'  =>  :'ECDHE',               :'authentication'  =>  :'ECDSA',               :'encryption'  =>  :'AES_128_CBC',       :'bits'  =>  128,  :'mac'  =>  :'SHA',        :'id'  =>  [0xC0, 0x09]},
    {:'name'  =>  :'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA',     :'keyexchange'  =>  :'ECDHE',               :'authentication'  =>  :'ECDSA',               :'encryption'  =>  :'AES_256_CBC',       :'bits'  =>  256,  :'mac'  =>  :'SHA',        :'id'  =>  [0xC0, 0x0A]},
    {:'name'  =>  :'TLS_ECDH_RSA_WITH_NULL_SHA',               :'keyexchange'  =>  :'ECDH',                :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'NULL',              :'bits'  =>  0,    :'mac'  =>  :'SHA',        :'id'  =>  [0xC0, 0x0B]},
    {:'name'  =>  :'TLS_ECDH_RSA_WITH_RC4_128_SHA',            :'keyexchange'  =>  :'ECDH',                :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'RC4_128',           :'bits'  =>  128,  :'mac'  =>  :'SHA',        :'id'  =>  [0xC0, 0x0C]},
    {:'name'  =>  :'TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA',       :'keyexchange'  =>  :'ECDH',                :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'3DES_EDE_CBC',      :'bits'  =>  168,  :'mac'  =>  :'SHA',        :'id'  =>  [0xC0, 0x0D]},
    {:'name'  =>  :'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA',        :'keyexchange'  =>  :'ECDH',                :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'AES_128_CBC',       :'bits'  =>  128,  :'mac'  =>  :'SHA',        :'id'  =>  [0xC0, 0x0E]},
    {:'name'  =>  :'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA',        :'keyexchange'  =>  :'ECDH',                :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'AES_256_CBC',       :'bits'  =>  256,  :'mac'  =>  :'SHA',        :'id'  =>  [0xC0, 0x0F]},
    {:'name'  =>  :'TLS_ECDHE_RSA_WITH_NULL_SHA',              :'keyexchange'  =>  :'ECDHE',               :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'NULL',              :'bits'  =>  0,    :'mac'  =>  :'SHA',        :'id'  =>  [0xC0, 0x10]},
    {:'name'  =>  :'TLS_ECDHE_RSA_WITH_RC4_128_SHA',           :'keyexchange'  =>  :'ECDHE',               :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'RC4_128',           :'bits'  =>  128,  :'mac'  =>  :'SHA',        :'id'  =>  [0xC0, 0x11]},
    {:'name'  =>  :'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA',      :'keyexchange'  =>  :'ECDHE',               :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'3DES_EDE_CBC',      :'bits'  =>  168,  :'mac'  =>  :'SHA',        :'id'  =>  [0xC0, 0x12]},
    {:'name'  =>  :'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',       :'keyexchange'  =>  :'ECDHE',               :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'AES_128_CBC',       :'bits'  =>  128,  :'mac'  =>  :'SHA',        :'id'  =>  [0xC0, 0x13]},
    {:'name'  =>  :'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',       :'keyexchange'  =>  :'ECDHE',               :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'AES_256_CBC',       :'bits'  =>  256,  :'mac'  =>  :'SHA',        :'id'  =>  [0xC0, 0x14]},
    {:'name'  =>  :'TLS_ECDH_Anon_WITH_NULL_SHA',              :'keyexchange'  =>  :'ECDH',                :'authentication'  =>  :'Anon',                :'encryption'  =>  :'NULL',              :'bits'  =>  0,    :'mac'  =>  :'SHA',        :'id'  =>  [0xC0, 0x15]},
    {:'name'  =>  :'TLS_ECDH_Anon_WITH_RC4_128_SHA',           :'keyexchange'  =>  :'ECDH',                :'authentication'  =>  :'Anon',                :'encryption'  =>  :'RC4_128',           :'bits'  =>  128,  :'mac'  =>  :'SHA',        :'id'  =>  [0xC0, 0x16]},
    {:'name'  =>  :'TLS_ECDH_Anon_WITH_3DES_EDE_CBC_SHA',      :'keyexchange'  =>  :'ECDH',                :'authentication'  =>  :'Anon',                :'encryption'  =>  :'3DES_EDE_CBC',      :'bits'  =>  168,  :'mac'  =>  :'SHA',        :'id'  =>  [0xC0, 0x17]},
    {:'name'  =>  :'TLS_ECDH_Anon_WITH_AES_128_CBC_SHA',       :'keyexchange'  =>  :'ECDH',                :'authentication'  =>  :'Anon',                :'encryption'  =>  :'AES_128_CBC',       :'bits'  =>  128,  :'mac'  =>  :'SHA',        :'id'  =>  [0xC0, 0x18]},
    {:'name'  =>  :'TLS_ECDH_Anon_WITH_AES_256_CBC_SHA',       :'keyexchange'  =>  :'ECDH',                :'authentication'  =>  :'Anon',                :'encryption'  =>  :'AES_256_CBC',       :'bits'  =>  256,  :'mac'  =>  :'SHA',        :'id'  =>  [0xC0, 0x19]},
    {:'name'  =>  :'TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA',        :'keyexchange'  =>  :'SRP',                 :'authentication'  =>  :'SHA',                 :'encryption'  =>  :'3DES_EDE_CBC',      :'bits'  =>  168,  :'mac'  =>  :'SHA',        :'id'  =>  [0xC0, 0x1A]},
    {:'name'  =>  :'TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA',    :'keyexchange'  =>  :'SRP',                 :'authentication'  =>  :'SHA',                 :'encryption'  =>  :'3DES_EDE_CBC',      :'bits'  =>  168,  :'mac'  =>  :'SHA',        :'id'  =>  [0xC0, 0x1B]},
    {:'name'  =>  :'TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA',    :'keyexchange'  =>  :'SRP',                 :'authentication'  =>  :'SHA',                 :'encryption'  =>  :'3DES_EDE_CBC',      :'bits'  =>  168,  :'mac'  =>  :'SHA',        :'id'  =>  [0xC0, 0x1C]},
    {:'name'  =>  :'TLS_SRP_SHA_WITH_AES_128_CBC_SHA',         :'keyexchange'  =>  :'SRP',                 :'authentication'  =>  :'SHA',                 :'encryption'  =>  :'AES_128_CBC',       :'bits'  =>  128,  :'mac'  =>  :'SHA',        :'id'  =>  [0xC0, 0x1D]},
    {:'name'  =>  :'TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA',     :'keyexchange'  =>  :'SRP',                 :'authentication'  =>  :'SHA',                 :'encryption'  =>  :'AES_128_CBC',       :'bits'  =>  128,  :'mac'  =>  :'SHA',        :'id'  =>  [0xC0, 0x1E]},
    {:'name'  =>  :'TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA',     :'keyexchange'  =>  :'SRP',                 :'authentication'  =>  :'SHA',                 :'encryption'  =>  :'AES_128_CBC',       :'bits'  =>  128,  :'mac'  =>  :'SHA',        :'id'  =>  [0xC0, 0x1F]},
    {:'name'  =>  :'TLS_SRP_SHA_WITH_AES_256_CBC_SHA',         :'keyexchange'  =>  :'SRP',                 :'authentication'  =>  :'SHA',                 :'encryption'  =>  :'AES_256_CBC',       :'bits'  =>  256,  :'mac'  =>  :'SHA',        :'id'  =>  [0xC0, 0x20]},
    {:'name'  =>  :'TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA',     :'keyexchange'  =>  :'SRP',                 :'authentication'  =>  :'SHA',                 :'encryption'  =>  :'AES_256_CBC',       :'bits'  =>  256,  :'mac'  =>  :'SHA',        :'id'  =>  [0xC0, 0x21]},
    {:'name'  =>  :'TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA',     :'keyexchange'  =>  :'SRP',                 :'authentication'  =>  :'SHA',                 :'encryption'  =>  :'AES_256_CBC',       :'bits'  =>  256,  :'mac'  =>  :'SHA',        :'id'  =>  [0xC0, 0x22]},
    {:'name'  =>  :'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',  :'keyexchange'  =>  :'ECDHE',               :'authentication'  =>  :'ECDSA',               :'encryption'  =>  :'AES_128_CBC',       :'bits'  =>  128,  :'mac'  =>  :'SHA256',     :'id'  =>  [0xC0, 0x23]},
    {:'name'  =>  :'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',  :'keyexchange'  =>  :'ECDHE',               :'authentication'  =>  :'ECDSA',               :'encryption'  =>  :'AES_256_CBC',       :'bits'  =>  256,  :'mac'  =>  :'SHA384',     :'id'  =>  [0xC0, 0x24]},
    {:'name'  =>  :'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256',   :'keyexchange'  =>  :'ECDH',                :'authentication'  =>  :'ECDSA',               :'encryption'  =>  :'AES_128_CBC',       :'bits'  =>  128,  :'mac'  =>  :'SHA256',     :'id'  =>  [0xC0, 0x25]},
    {:'name'  =>  :'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384',   :'keyexchange'  =>  :'ECDH',                :'authentication'  =>  :'ECDSA',               :'encryption'  =>  :'AES_256_CBC',       :'bits'  =>  256,  :'mac'  =>  :'SHA384',     :'id'  =>  [0xC0, 0x26]},
    {:'name'  =>  :'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',    :'keyexchange'  =>  :'ECDHE',               :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'AES_128_CBC',       :'bits'  =>  128,  :'mac'  =>  :'SHA256',     :'id'  =>  [0xC0, 0x27]},
    {:'name'  =>  :'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',    :'keyexchange'  =>  :'ECDHE',               :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'AES_256_CBC',       :'bits'  =>  256,  :'mac'  =>  :'SHA384',     :'id'  =>  [0xC0, 0x28]},
    {:'name'  =>  :'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256',     :'keyexchange'  =>  :'ECDH',                :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'AES_128_CBC',       :'bits'  =>  128,  :'mac'  =>  :'SHA256',     :'id'  =>  [0xC0, 0x29]},
    {:'name'  =>  :'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384',     :'keyexchange'  =>  :'ECDH',                :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'AES_256_CBC',       :'bits'  =>  256,  :'mac'  =>  :'SHA384',     :'id'  =>  [0xC0, 0x2A]},
    {:'name'  =>  :'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',  :'keyexchange'  =>  :'ECDHE',               :'authentication'  =>  :'ECDSA',               :'encryption'  =>  :'AES_128_GCM',       :'bits'  =>  128,  :'mac'  =>  :'SHA256',     :'id'  =>  [0xC0, 0x2B]},
    {:'name'  =>  :'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',  :'keyexchange'  =>  :'ECDHE',               :'authentication'  =>  :'ECDSA',               :'encryption'  =>  :'AES_256_GCM',       :'bits'  =>  256,  :'mac'  =>  :'SHA384',     :'id'  =>  [0xC0, 0x2C]},
    {:'name'  =>  :'TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256',   :'keyexchange'  =>  :'ECDH',                :'authentication'  =>  :'ECDSA',               :'encryption'  =>  :'AES_128_GCM',       :'bits'  =>  128,  :'mac'  =>  :'SHA256',     :'id'  =>  [0xC0, 0x2D]},
    {:'name'  =>  :'TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384',   :'keyexchange'  =>  :'ECDH',                :'authentication'  =>  :'ECDSA',               :'encryption'  =>  :'AES_256_GCM',       :'bits'  =>  256,  :'mac'  =>  :'SHA384',     :'id'  =>  [0xC0, 0x2E]},
    {:'name'  =>  :'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',    :'keyexchange'  =>  :'ECDHE',               :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'AES_128_GCM',       :'bits'  =>  128,  :'mac'  =>  :'SHA256',     :'id'  =>  [0xC0, 0x2F]},
    {:'name'  =>  :'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',    :'keyexchange'  =>  :'ECDHE',               :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'AES_256_GCM',       :'bits'  =>  256,  :'mac'  =>  :'SHA384',     :'id'  =>  [0xC0, 0x30]},
    {:'name'  =>  :'TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256',     :'keyexchange'  =>  :'ECDH',                :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'AES_128_GCM',       :'bits'  =>  128,  :'mac'  =>  :'SHA256',     :'id'  =>  [0xC0, 0x31]},
    {:'name'  =>  :'TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384',     :'keyexchange'  =>  :'ECDH',                :'authentication'  =>  :'RSA',                 :'encryption'  =>  :'AES_256_GCM',       :'bits'  =>  256,  :'mac'  =>  :'SHA384',     :'id'  =>  [0xC0, 0x32]},
    {:'name'  =>  :'TLS_ECDHE_PSK_WITH_RC4_128_SHA',           :'keyexchange'  =>  :'ECDHE',               :'authentication'  =>  :'PSK',                 :'encryption'  =>  :'RC4_128',           :'bits'  =>  128,  :'mac'  =>  :'SHA',        :'id'  =>  [0xC0, 0x33]},
    {:'name'  =>  :'TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA',      :'keyexchange'  =>  :'ECDHE',               :'authentication'  =>  :'PSK',                 :'encryption'  =>  :'3DES_EDE_CBC',      :'bits'  =>  168,  :'mac'  =>  :'SHA',        :'id'  =>  [0xC0, 0x34]},
    {:'name'  =>  :'TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA',       :'keyexchange'  =>  :'ECDHE',               :'authentication'  =>  :'PSK',                 :'encryption'  =>  :'AES_128_CBC',       :'bits'  =>  128,  :'mac'  =>  :'SHA',        :'id'  =>  [0xC0, 0x35]},
    {:'name'  =>  :'TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA',       :'keyexchange'  =>  :'ECDHE',               :'authentication'  =>  :'PSK',                 :'encryption'  =>  :'AES_256_CBC',       :'bits'  =>  256,  :'mac'  =>  :'SHA',        :'id'  =>  [0xC0, 0x36]},
    {:'name'  =>  :'TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256',    :'keyexchange'  =>  :'ECDHE',               :'authentication'  =>  :'PSK',                 :'encryption'  =>  :'AES_128_CBC',       :'bits'  =>  128,  :'mac'  =>  :'SHA256',     :'id'  =>  [0xC0, 0x37]},
    {:'name'  =>  :'TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384',    :'keyexchange'  =>  :'ECDHE',               :'authentication'  =>  :'PSK',                 :'encryption'  =>  :'AES_256_CBC',       :'bits'  =>  256,  :'mac'  =>  :'SHA384',     :'id'  =>  [0xC0, 0x38]},
    {:'name'  =>  :'TLS_ECDHE_PSK_WITH_NULL_SHA',              :'keyexchange'  =>  :'ECDHE',               :'authentication'  =>  :'PSK',                 :'encryption'  =>  :'NULL',              :'bits'  =>  0,    :'mac'  =>  :'SHA',        :'id'  =>  [0xC0, 0x39]},
    {:'name'  =>  :'TLS_ECDHE_PSK_WITH_NULL_SHA256',           :'keyexchange'  =>  :'ECDHE',               :'authentication'  =>  :'PSK',                 :'encryption'  =>  :'NULL',              :'bits'  =>  0,    :'mac'  =>  :'SHA256',     :'id'  =>  [0xC0, 0x3A]},
    {:'name'  =>  :'TLS_ECDHE_PSK_WITH_NULL_SHA384',           :'keyexchange'  =>  :'ECDHE',               :'authentication'  =>  :'PSK',                 :'encryption'  =>  :'NULL',              :'bits'  =>  0,    :'mac'  =>  :'SHA384',     :'id'  =>  [0xC0, 0x3B]},
    {:'name'  =>  :'SSL_RSA_FIPS_WITH_DES_CBC_SHA',            :'keyexchange'  =>  :'RSA_FIPS',            :'authentication'  =>  :'RSA_FIPS',            :'encryption'  =>  :'DES_CBC',           :'bits'  =>  56,   :'mac'  =>  :'SHA',        :'id'  =>  [0xFE, 0xFE]},
    {:'name'  =>  :'SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA',       :'keyexchange'  =>  :'RSA_FIPS',            :'authentication'  =>  :'RSA_FIPS',            :'encryption'  =>  :'3DES_EDE_CBC',      :'bits'  =>  168,  :'mac'  =>  :'SHA',        :'id'  =>  [0xFE, 0xFF]},
    {:'name'  =>  :'SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA',       :'keyexchange'  =>  :'RSA_FIPS',            :'authentication'  =>  :'RSA_FIPS',            :'encryption'  =>  :'3DES_EDE_CBC',      :'bits'  =>  168,  :'mac'  =>  :'SHA',        :'id'  =>  [0xFF, 0xE0]},
    {:'name'  =>  :'SSL_RSA_FIPS_WITH_DES_CBC_SHA',            :'keyexchange'  =>  :'RSA_FIPS',            :'authentication'  =>  :'RSA_FIPS',            :'encryption'  =>  :'DES_CBC',           :'bits'  =>  56,   :'mac'  =>  :'SHA',        :'id'  =>  [0xFF, 0xE1]}
]


def filter(array, procs)
  procs.empty? ? array : filter((array.select! &(procs.shift)), procs)
end

options = OpenStruct.new
options.filters = []
options.verbose = false
options.port = 443

OptionParser.new do |opts|
  opts.banner = 'Usage: ssl-inspector.rb [options]'
  opts.on('-a', '--authentication ALGORITHM', 'Specify an authentication algorithm') { |a| options.filters << Proc.new { |el| el[:'authentication'] == a.to_sym } }
  opts.on('-b', '--bits [<|<=|>=|>]SIZE', 'Specify an encryption key size') do |b|
    /(?<o><|>|<=|>=)?(?<d>\d+)/ =~ b
    options.filters << Proc.new { |el| el[:'bits'].send(o.nil? ? '==' : o, d.to_i) }
  end
  opts.on('-e', '--encryption ALGORITHM', 'Specify an encryption algorithm')         { |e| options.filters << Proc.new { |el| el[:'encryption'] == e.to_sym } }
  opts.on('-h', '--host HOST', 'Specify target host')                                { |h| options.host = h }
  opts.on('-k', '--keyexchange ALGORITHM', 'Specify a keyexchange algorithm')        { |k| options.filters << Proc.new { |el| el[:'keyexchange'] == k.to_sym } }
  opts.on('-m', '--mac ALGORITHM', 'Specify a MAC algorithm')                        { |m| options.filters << Proc.new { |el| el[:'mac'] == m.to_sym } }
  opts.on('-n', '--name NAME', 'Specify a cipher suite partial or full name')        { |n| options.filters << Proc.new { |el| el[:'name'] =~ /#{n}/ } }
  opts.on('-p', '--port PORT', 'Specify target port')                                { |p| options.port = p }
  opts.on('-s', '--specification PROTOCOL', 'Specification SSLv3 or TLSv1.{0,1,2}')  { |s| options.spec = s }
  opts.on('-v', '--verbose', 'Run in verbose mode')                                  { |v| options.verbose = v }
  opts.on_tail('-h', '--help', 'Show this message')                                  { puts opts ; exit }
end.parse!

abort('You must specify a target host') if options.host.nil?
abort('You must specify a protocol version') if options.spec.nil?

suites = options.filters.empty? ? CIPHER_SUITES : filter(CIPHER_SUITES, options.filters)
protocol = PROTOCOLS[options.spec.to_sym]

suites.each do |suite|

  handshake = [
      0x16,
      protocol,
      0x00, 0x2D,
      0x01,
      0x00, 0x00, 0x29,
      protocol,
      0x53, 0x4A, 0x84, 0xA9,
      0x00, 0x01, 0x02, 0x03,   0x04, 0x05, 0x06, 0x07,   0x08, 0x09, 0x0A, 0x0B,
      0x0C, 0x0D, 0x0E, 0x0F,   0x10, 0x11, 0x12, 0x13,   0x14, 0x15, 0x16, 0x17,
      0x18, 0x19, 0x1A, 0x1B,
      0x00,
      0x00, 0x02,
      suite[:'id'],
      0x01,
      0x00
  ]

  s = TCPSocket.new(options.host, options.port)
  s.write(handshake.flatten!.pack('C*'))
  server_hello = s.read(1).unpack('C')[0]
  result = 'DISABLED'

  if server_hello == 22
    h_maj_version, h_min_version = s.read(2).unpack('C*')
    result = (server_hello && (protocol == [h_maj_version.to_i, h_min_version.to_i])) ? 'ENABLED' : 'DISABLED'
  end

  printf("%-50s [%s]\n", suite[:'name'], result) unless !(result == 'ENABLED' || options.verbose)
  STDOUT.flush

  s.close

end