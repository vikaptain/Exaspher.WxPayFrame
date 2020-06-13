﻿namespace APPBackstage.Services.WxMerchant
{
	/// <summary>
	/// 配置文件
	/// </summary>
	public class WxConfig
	{
		/// <summary>
		/// 公众号ID
		/// </summary>
		public static string AppId = "wx82fbe1be460a3cbf";

		/// <summary>
		/// 公衆號Secret
		/// </summary>
		public static string AppSecret = "4f043c5bc0c493480be5f6ddd5eb4834";

		/// <summary>
		/// 開放平臺ID
		/// </summary>
		public static string OpenId = "";

		/// <summary>
		/// 商户号
		/// </summary>
		public static string MchId = "1596462601";

		/// <summary>
		/// 商户名稱
		/// </summary>
		public static string MchName = "重庆汇嘉时代电子商务有限公司";

		/// <summary>
		/// 日志配置
		/// </summary>
		public static int LogLevel = 3;

		/// <summary>
		/// 证书编号
		/// </summary>
		public static string SerialNo = "4F1EC862B4982C69C3BCAE34FC4D36728C857B3E";

		/// <summary>
		/// 证书文件路径
		/// </summary>
		public static string CertPath = @"cert\merchant_cert.p12";

		/// <summary>
		/// 私钥证书路径
		/// </summary>
		public static string CertPrivatePath = @"cert\private_key.pem";

		/// <summary>
		/// 公钥证书路径
		/// </summary>
		public static string CertPublicPath = @"cert\public_key.pem";

		/// <summary>
		/// 证书Secret
		/// </summary>
		public static string CertSecret = "4fe39D4b90104586162cfDc68f874A68";

		/// <summary>
		/// 证书密钥
		/// </summary>
		public static string CertPwd = "1596462601";

		/// <summary>
		/// Encryption密钥
		/// </summary>
		public static string EncryptionKey = "H+sD20O9";

		/// <summary>
		/// 支付完成后的回调处理页面
		/// </summary>
		public static string TenPayV3Nofify = "http://wx.hjsdgf.cn/PayEntrance/PayNotify";

		/// <summary>
		/// 私钥
		/// </summary>
		public static string PrivateKey = @"MIIEwAIBADANBgkqhkiG9w0BAQEFAASCBKowggSmAgEAAoIBAQCuer7ujvbwQfjD
oPDC5k96oNeiAhK16B4EZJX1iv2xapfaeVlTHE3XUQmW3sFcZk7MC3zQK3qj5SVr
VkD41dg/KdKoWx589O75Mm3qhKl9nqR2jth07ruAEk3dbKRNbS1JvrXpa1rLDs/y
7kNzdoehFytekpTbCwVvhgRFYG65ECM/JE6gHv2TpOcsDtvz2D+MdeS4l3XRgiQf
khtRdRP59mwa+wI7BNWIphHMbQQ9Kbl/fkxlIsjM5RZdLJ2il6DYceBeiTLX2IpW
oitc5sDZpnwNYfZVQEu/JUALX5U4BK9IJwJRvK7lKPSTXYpC4R+Xxr1CnCFd0ILf
9lyUMCnzAgMBAAECggEBAIpjpz82O9zSpsobw/sCi7W7D21bcZXAttZLJbos9Q2c
ezd5GoVWJNOMXivBIOL17rfewK+oXMzUOnrJXh1AGBX5STHpm+QGrekPu6jQclLF
2rKCmGMe2684VXQz8JnM56ffURAD6261n/CSVQOm1urJosePQev+8N/FD2wrkYbM
Wo3dIXBdJIT1U9n9W76nUnAUVToCGhXLf7G3yUDL02Dy1e49l0VdtrJlrDJwhngA
HCZQpS56737NnFtT9PC6r+hsTzTn1xeewzxm7Q2LZmIfj0FfVacGCwWsG3WGisEo
KojYLx9702hixCtxFiNZ0nxRBkNak6ao8/tzhB0olWECgYEA5ZyZuWTiQlARXDrZ
+7iE61B8RDkqC0UlL2a0QSIa8B+xM48VLBMOhR65W9VYIQkeN2GqDZEuDdtOpR95
Tj+c6eAtgM17nToinFiTHjbjLtHD9frbNeWSVfsJYcE0+t4aOGyUUDV9mfbmF99n
5iqnZ7lDBJvsm3h7jdc01qrmEKMCgYEAwogZ6kCEzX7QQe8tLLmQhSp2n6xy8kYC
JMw2zjg2KbghTepGizgqQutHliyuLf6r1Pr7Tp3SN4KH+2xqkD0sRASIrF526avs
sKg99WS8JTLEGxbw6snV+DDECZTIgMDSUbMP+FDrEFwAWBCvEI2TW1H7DZkzvbzi
xAyk5t+1BnECgYEAxeh897dk7hNlY0G2sakRqGHvOj6rZptqubiklZ936JDog7BI
Z3zlfwhEbEsvcwoQ6Vtc3+TK9VaaKuk9/ZwG++8mSWbTrWl2e5w88kYM+0YCyfo3
B/WgdEu0gnWt3K2jnA66p4fzgsm0+c6uF02cjWK5yTc8caUfmdpsyLr1IlECgYEA
kKceBif12Mzs1aqhv/k4sx0xWmikjO1sGKrWMiBwfjNSaJrF3C5mlp5X/B67Yq5W
XihHiV0n/WkN7vLehuVGLknky6/u4rGabn6cnAZNNaf7VV2Ixj5R4p14mNtPARbh
DimFvZOGSALxqoq1cyyjn6tlcOY0KGn1ge0ZDijZdrECgYEAvM1u51zibVU8lp5T
76RkEVWoVNThkW3yWy2wyFU3OT25QC583sCzLLQ2EAbGX4MEf1n6rHCduUuduDs8
uJI60i7Fxfr6wEefozHLvO/JDBhdwzzYDemTQKxR708ZO/IV1zhFIdWXy3HtKnHK
qkIlerjtpwO6pXtg0tUgqt74ySI=";

		/// <summary>
		/// 公钥
		/// </summary>
		public static string PublicKeyStr = @"MIID3DCCAsSgAwIBAgIUd5amLEXx+DsLj17VmJ3pEl10vTQwDQYJKoZIhvcNAQEL
BQAwXjELMAkGA1UEBhMCQ04xEzARBgNVBAoTClRlbnBheS5jb20xHTAbBgNVBAsT
FFRlbnBheS5jb20gQ0EgQ2VudGVyMRswGQYDVQQDExJUZW5wYXkuY29tIFJvb3Qg
Q0EwHhcNMjAwNjAxMDIxNTM4WhcNMjUwNTMxMDIxNTM4WjBuMRgwFgYDVQQDDA9U
ZW5wYXkuY29tIHNpZ24xEzARBgNVBAoMClRlbnBheS5jb20xHTAbBgNVBAsMFFRl
bnBheS5jb20gQ0EgQ2VudGVyMQswCQYDVQQGDAJDTjERMA8GA1UEBwwIU2hlblpo
ZW4wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCxoY0+aK197pYH9ODd
8kRZj6ROrry7BeYBfK8TnA3jW7tv13uZ+OdDw50rtBEnlS8mZgtjZgP+uoLOh9zO
dU2XzL/UkRTwv/lmgyDe+hKCFxuoQwUYfeAZhMfcd45uthOR9iz0l2vK1W0fsOOz
ThMiuuobvOq8atCgumRabLsJPSObCaa3FssKJ33puz63xa6EGiislTt/CHUh1J/V
2+cSLQq/Xk8cdrnK8fIj8HgJCR0cqUIb6VeeATRUpY5RLSoXsyk5ogAq9sGf4Fcd
Nx3/mKOxzx6Y6UkooCtayf7qHojIC0Z5FhRmRQnthh3Gb8+jiONmUDAyMyPrOCqB
nSi9AgMBAAGjgYEwfzAJBgNVHRMEAjAAMAsGA1UdDwQEAwIE8DBlBgNVHR8EXjBc
MFqgWKBWhlRodHRwOi8vZXZjYS5pdHJ1cy5jb20uY24vcHVibGljL2l0cnVzY3Js
P0NBPTFCRDQyMjBFNTBEQkMwNEIwNkFEMzk3NTQ5ODQ2QzAxQzNFOEVCRDIwDQYJ
KoZIhvcNAQELBQADggEBAAJJAmT4Q/eNquGT8gZT2wE4Y+/FPaZDhJKfxMOAXPh+
Rt3VDdnwvmXTIMkN8ky7kBdZjg1/lUrW/Jw6zwPxQFdb1EPq8XVJxPgO26FeOfKm
ScEGrlBg2HU/ji5ozME/Sc9qrC6dVb81SoDrMd2yQIeZ/IBMHf+NReYQODhwceeD
O5Pd6055Q3kHp5tD51bM1zWDHIyvmMhyyb6DRGBlICST1P/GokvwrmaSIgvmyaE+
GL6+6Z/Caueqp1e6kDAijBEzm26QQCrRTxP4jbfwbLsHpIKOsTQwPOAmgMXd36Hb
l0H0Mi1klkIAryQjQoEjqP54GZroceQbX6MYyLAlyvw=";
	}
}