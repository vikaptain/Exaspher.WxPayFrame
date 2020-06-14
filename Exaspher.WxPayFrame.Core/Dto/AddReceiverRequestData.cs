using System;
using System.Security.Cryptography;
using System.Text;

namespace Exaspher.WxPayFrame.Core.Dto
{
	public class AddReceiverRequestData
	{
		public string appid { get; set; }

		public string type { get; set; }

		public string account { get; set; }

		public string name { get; set; }

		public string encrypted_name { get; set; }

		public string relation_type { get; set; }

		public void Encrypt(RSA rsa)
		{
			if (!string.IsNullOrWhiteSpace(encrypted_name))
			{
				this.encrypted_name = Convert.ToBase64String(rsa.Encrypt(Encoding.UTF8.GetBytes(encrypted_name), RSAEncryptionPadding.OaepSHA1));
			}
		}
	}
}