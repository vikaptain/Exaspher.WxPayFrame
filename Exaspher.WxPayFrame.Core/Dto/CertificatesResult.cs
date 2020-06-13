namespace Exaspher.WxPayFrame.Core.Dto
{
	public class CertificatesResult
	{
		public CertificatesResultData[] data { get; set; }
	}

	public class CertificatesResultData
	{
		public string serial_no { get; set; }

		public string effective_time { get; set; }

		public string expire_time { get; set; }

		public EncryptCertificate encrypt_certificate { get; set; }
	}

	public class EncryptCertificate
	{
		public string algorithm { get; set; }

		public string nonce { get; set; }

		public string associated_data { get; set; }

		public string ciphertext { get; set; }
	}
}