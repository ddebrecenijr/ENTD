TLS_VERSIONS = {
    0x300 : "SSLv3",
    0x301 : "TLSv1",
    0x302 : "TLSv1.1",
    0x303 : "TLSv1.2"
}

HANDSHAKE_TYPES = {
    0x00: "Hello_Request",
    0x01: "Client_Hello",
    0x02: "Server_Hello",
    0x0B: "Certificate",
    0x0C: "Server_Key_Exchange",
    0x0D: "Certificate_Request",
    0x0E: "Server_Done",
    0x0F: "Certificate_Verify",
    0x10: "Client_Key_Exchange",
    0x14: "Finished"
}

CIPHERSUITES = {
    # HIGH PRIORITY
    0x009F : ['TLS_DHE_RSA_WITH_AES_256_GCM_SHA384', 'DHE-RSA-AES256-GCM-SHA384'],
    0X009E : ['TLS_DH_RSA_WITH_AES_128_GCM_SHA256', 'DHE-RSA-AES128-GCM-SHA256'],
    0XC030 : ['TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', 'ECDHE-RSA-AES256-GCM-SHA384'],
    0XC02F : ['TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 'ECDHE-RSA-AES128-GCM-SHA256'],
    # MEDIUM PRIORITY
    0X006B : ['TLS_DHE_RSA_WITH_AES_256_CBC_SHA256', 'DHE-RSA-AES256-SHA256'],
    0X0067 : ['TLS_DHE_RSA_WITH_AES_128_CBC_SHA256', 'DHE-RSA-AES128-SHA256'],
    0XC028 : ['TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384', 'ECDHE-RSA-AES256-SHA384'],
    0XC027 : ['TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256', 'ECDHE-RSA-AES128-SHA256'],
    0XC014 : ['TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA', 'ECDHE-RSA-AES256-SHA'],
    0XC013 : ['TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', 'ECDHE-RSA-AES128-SHA'],
    0X009D : ['TLS_RSA_WITH_AES_256_GCM_SHA384', 'AES256-GCM-SHA384'],
    0X009C : ['TLS_RSA_WITH_AES_128_GCM_SHA256', 'AES128-GCM-SHA256'],
    0X003D : ['TLS_RSA_WITH_AES_256_CBC_SHA256', 'AES256-SHA256'],
    0X003C : ['TLS_RSA_WITH_AES_128_CBC_SHA256', 'AES128-SHA256'],
    0X0035 : ['TLS_RSA_WITH_AES_256_CBC_SHA', 'AES256-SHA'],
    0X002F : ['TLS_RSA_WITH_AES_128_CBC_SHA', 'AES128-SHA'],
    # LOW PRIORITY
    0X000A : ['TLS_RSA_WITH_3DES_EDE_CBC_SHA', 'DES-CBC3-SHA'],
    0X0039 : ['TLS_DHE_RSA_WITH_AES_256_CBC_SHA', 'DHE-RSA-AES256-SHA'],
    0X0033 : ['TLS_DHE_RSA_WITH_AES_128_CBC_SHA', 'DHE-RSA-AES128-SHA']
}
