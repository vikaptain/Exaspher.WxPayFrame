using Exaspher.WxPayFrame.Core.Dto;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Exaspher.WxPay.Core
{
	public class WxPayService : IWxPayService
	{
		// private readonly IConfiguration _configuration;
		// private readonly IHostEnvironment _hostEnvironment;

		private readonly string _mchId;
		private readonly string _serialNo;
		private readonly string _appId;

		public WxPayService()
		{
			//_configuration = configuration;
			//_hostEnvironment = hostEnvironment;

			_mchId = ConfigurationManager.AppSettings["WxPay:MchId"];  //_configuration.GetValue<string>("WxPay:MchId");
			_serialNo = ConfigurationManager.AppSettings["WxPay:SerialNo"]; // _configuration.GetValue<string>("WxPay:SerialNo");
			_appId = "wx82fbe1be460a3cbf";
		}

		public async Task<object> ApplyMent()
		{
			var nonce = GenerateNonce();

			#region 传入数据

			var applyment = new ApplyMentDto();
			applyment.BusinessCode = "X00000000001";
			applyment.ContactInfo = new ApplyMentContactInfoDto()
			{
				ContactName = "张三",
				// OpenId = "1312321",
				ContactIdNumber = "511111111111111111",
				MobilePhone = "13333333333",
				ContactEmail = "11@gmail.com",
			};
			applyment.SubjectInfo = new ApplyMentSubjectInfo()
			{
				SubjectType = "SUBJECT_TYPE_INDIVIDUAL",
				BusinessLicenseInfo = new ApplyMentBusinessLicenseInfo()
				{
					LicenseCopy = "tV7icXfN8VX58X0D187-NV08cFGRlx6LPg261cpQDI-asaq-0MXen3N7OVE5lDbStaS8nBBbBlv6hL3er8bDK-djRp4PtWGArfr9Numqxsk",
					LicenseNumber = "91440300MA5EYUKH2K",
					MerchantName = "张三餐饮店",
					LegalPerson = "张三"
				},
				IdentityInfo = new ApplyMentIdentityInfo()
				{
					IdDocType = "IDENTIFICATION_TYPE_IDCARD",
					IdCardInfo = new ApplyMentIdCardInfo()
					{
						IdCardCopy = "tV7icXfN8VX58X0D187-NV08cFGRlx6LPg261cpQDI-asaq-0MXen3N7OVE5lDbStaS8nBBbBlv6hL3er8bDK-djRp4PtWGArfr9Numqxsk",
						IdCardNational = "tV7icXfN8VX58X0D187-NV08cFGRlx6LPg261cpQDI-asaq-0MXen3N7OVE5lDbStaS8nBBbBlv6hL3er8bDK-djRp4PtWGArfr9Numqxsk",
						IdCardName = "张三",
						IdCardNumber = "511111111111111111",
						CardPeriodBegin = "2010-01-01",
						CardPeriodEnd = "长期",
					},
					Owner = true
				},
			};
			applyment.BusinessInfo = new ApplyMentBusinessInfo()
			{
				MerchantShortName = "张三餐饮店",
				ServicePhone = "13333333333",
				SalesInfo = new ApplyMentSalesInfo()
				{
					SalesScenesType = new List<string>() { "SALES_SCENES_STORE" },
					BizStorInfo = new ApplyMentBizStorInfo()
					{
						BizStoreName = "张三餐饮店",
						BizAddressCode = "440305",
						BizStoreAddress = "南山区xx大厦x层xxxx室",
						StoreEntrancePic = new List<string>()
						{
							"tV7icXfN8VX58X0D187-NV08cFGRlx6LPg261cpQDI-asaq-0MXen3N7OVE5lDbStaS8nBBbBlv6hL3er8bDK-djRp4PtWGArfr9Numqxsk"
						},
						IndoorPic = new List<string>()
						{
							"tV7icXfN8VX58X0D187-NV08cFGRlx6LPg261cpQDI-asaq-0MXen3N7OVE5lDbStaS8nBBbBlv6hL3er8bDK-djRp4PtWGArfr9Numqxsk"
						}
					}
				}
			};
			applyment.SettlementInfo = new ApplyMentSettlementInfo()
			{
				SettlementId = "719",
				QualificationType = "餐饮",
				Qualifications = new List<string>()
				{
					"tV7icXfN8VX58X0D187-NV08cFGRlx6LPg261cpQDI-asaq-0MXen3N7OVE5lDbStaS8nBBbBlv6hL3er8bDK-djRp4PtWGArfr9Numqxsk"
				},
				ActivitiesAdditions = new List<string>(),
			};
			applyment.Encrypt(GetPublicCertificate().PublicKey.Key as RSA);

			#endregion 传入数据

			var jsonContent = JsonConvert.SerializeObject(applyment); //.Serialize(applyment);

			var httpHandler = new HttpHandler(_mchId, _serialNo, GetPublicCertificate().SerialNumber, GetPrivateCertificate(), GetMerchantCertificate());
			var client = new HttpClient(httpHandler);

			var request = new HttpRequestMessage(HttpMethod.Post,
				"https://api.mch.weixin.qq.com/v3/applyment4sub/applyment/")
			{
				Content = new StringContent(jsonContent, Encoding.UTF8, "application/json")
			};

			var response = await client.SendAsync(request);
			var result = await response.Content.ReadAsStringAsync();
			if (response.StatusCode != HttpStatusCode.OK)
			{
			}

			return string.Empty;
		}

		public async Task GetCertificates()
		{
			HttpClient client = new HttpClient();

			//var mchid = _configuration.GetValue<string>("WxPay:MchId");
			//var serial_no = _configuration.GetValue<string>("WxPay:SerialNo");

			var nonce_str = Guid.NewGuid().ToString();
			TimeSpan ts = DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, 0);
			var timestamp = Convert.ToInt64(ts.TotalSeconds).ToString();

			HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, "https://api.mch.weixin.qq.com/v3/certificates");

			client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("WECHATPAY2-SHA256-RSA2048", await BuildAuthAsync(request, _mchId, _serialNo, nonce_str));
			client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

			var response = await client.SendAsync(request);
			var result = await response.Content.ReadAsStringAsync();
			if (response.StatusCode != HttpStatusCode.OK)
			{
			}
		}

		public async Task<string> Upload(string fileName, byte[] buffer)
		{
			var boundary = $"--{DateTime.Now.Ticks:x}";

			#region 文件SHA256

			HashAlgorithm algorithm = SHA256.Create();
			var hashBytes = algorithm.ComputeHash(buffer);

			var sb = new StringBuilder();
			foreach (var b in hashBytes)
			{
				sb.Append(Convert.ToString(b, 16).PadLeft(2, '0'));
			}

			var sha256 = sb.ToString().ToUpper();

			#endregion 文件SHA256

			var meta = new
			{
				sha256 = sha256,
				filename = fileName
			};

			var jsonContent = JsonConvert.SerializeObject(meta);

			var httpHandler = new HttpHandler(_mchId, _serialNo, GetPublicCertificate().SerialNumber, GetPrivateCertificate(), GetMerchantCertificate(), jsonContent);
			var client = new HttpClient(httpHandler);
			using var requestContent = new MultipartFormDataContent(boundary);
			requestContent.Headers.ContentType = MediaTypeHeaderValue.Parse("multipart/form-data"); //这里必须添加
			requestContent.Add(new StringContent(jsonContent, Encoding.UTF8, "application/json"), "\"meta\"");

			var byteArrayContent = new ByteArrayContent(buffer);
			byteArrayContent.Headers.ContentType = new MediaTypeHeaderValue("image/jpg");
			requestContent.Add(byteArrayContent, "\"file\"", "\"" + meta.filename + "\"");  //这里主要必须要双引号
			using var response = await client.PostAsync("https://api.mch.weixin.qq.com/v3/merchant/media/upload", requestContent);
			using var responseContent = response.Content;
			var responseBody = await responseContent.ReadAsStringAsync(); //这里就可以拿到图片id了
																		  // return ResultHelper.QuickReturn(responseBody);
			return string.Empty;
			//}
		}

		protected async Task<string> BuildAuthAsync(HttpRequestMessage request, string mchid, string serialNo, string nonce, string jsonStr = "")
		{
			string method = request.Method.ToString();
			string body = "";
			if (method == "POST" || method == "PUT" || method == "PATCH")
			{
				var content = request.Content;
				if (content is StringContent)
				{
					body = await content.ReadAsStringAsync();
				}

				if (string.IsNullOrWhiteSpace(body))
				{
					body = jsonStr;
				}
			}

			string uri = request.RequestUri.PathAndQuery;
			var timestamp = DateTimeOffset.Now.ToUnixTimeSeconds();
			// string nonce = Path.GetRandomFileName();

			string message = $"{method}\n{uri}\n{timestamp}\n{nonce}\n{body}\n";
			string signature = string.Empty; // Sign(message);
			return $"mchid=\"{mchid}\",nonce_str=\"{nonce}\",timestamp=\"{timestamp}\",serial_no=\"{serialNo}\",signature=\"{signature}\"";
		}

		//protected string Sign(string message)
		//{
		//	// NOTE： 私钥不包括私钥文件起始的-----BEGIN PRIVATE KEY-----
		//	//        亦不包括结尾的-----END PRIVATE KEY-----

		//	byte[] keyData = Convert.FromBase64String(privateKey);
		//	using (CngKey cngKey = CngKey.Import(keyData, CngKeyBlobFormat.Pkcs8PrivateBlob))
		//	using (RSACng rsa = new RSACng(cngKey))
		//	{
		//		byte[] data = System.Text.Encoding.UTF8.GetBytes(message);
		//		return Convert.ToBase64String(rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
		//	}

		//	return string.Empty;
		//}

		public X509Certificate2 GetPublicCertificate()
		{
			var path = AppDomain.CurrentDomain.BaseDirectory + ConfigurationManager.AppSettings["WxPay:PublicKey"]; // _configuration.GetValue<string>("WxPay:PublicKey");
			var cert = new X509Certificate2(path, string.Empty,
				X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.MachineKeySet);
			// cert.PublicKey.Key
			return cert;

			//var path = _hostEnvironment.ContentRootPath + _configuration.GetValue<string>("WxPay:PublicKey");
			//var pemContents = System.IO.File.ReadAllText(path);
			//const string RsaPublicKeyHeader = "-----BEGIN CERTIFICATE-----";
			//const string RsaPublicKeyFooter = "-----END CERTIFICATE-----";

			//if (!pemContents.StartsWith(RsaPublicKeyHeader))
			//{
			//	throw new InvalidOperationException("公钥加载失败");
			//}
			//var endIdx = pemContents.IndexOf(
			//	RsaPublicKeyFooter,
			//	RsaPublicKeyHeader.Length,
			//	StringComparison.Ordinal);

			//var base64 = pemContents.Substring(
			//	RsaPublicKeyHeader.Length,
			//	endIdx - RsaPublicKeyHeader.Length);

			//var der = Convert.FromBase64String(base64);
			//var rsa = RSA.Create();
			//rsa.ImportRSAPrivateKey(der, out _);
			//return rsa;
		}

		public RSA GetPrivateCertificate()
		{
			return null;

			//var path = AppDomain.CurrentDomain.BaseDirectory + ConfigurationManager.AppSettings["WxPay:PrivateKey"];
			//var cert = new X509Certificate2(path, ConfigurationManager.AppSettings["WxPay:PrivateKeyPassword"],
			//	X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.MachineKeySet);
			//return cert.PrivateKey as RSA;
		}

		private string GenerateNonce()
		{
			return Guid.NewGuid().ToString();
		}

		public X509Certificate2 GetMerchantCertificate()
		{
			//_hostEnvironment.ContentRootPath + _configuration.GetValue<string>("WxPay:MerchantCertificate");
			var path = AppDomain.CurrentDomain.BaseDirectory + ConfigurationManager.AppSettings["WxPay:MerchantCertificate"];
			// _configuration.GetValue<string>("WxPay:PrivateKeyPassword")
			var cert = new X509Certificate2(path, ConfigurationManager.AppSettings["WxPay:PrivateKeyPassword"],
				X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.MachineKeySet);
			// var rsa = RSA.Create();
			return cert;
		}

		public void UnifiedOrder()
		{
			var data = new SortedDictionary<string, object>();
			data.Add("openid", "oPFdmxF0Sk1YVYi_IWafv7MR3_pI");
			data.Add("body", "商品名称测试");
			data.Add("attach", "支付测试");
			data.Add("out_trade_no", "1415659990");
			data.Add("sub_mch_id", "1600105465");
			data.Add("total_fee", 1);
			data.Add("time_start", DateTime.Now.ToString("yyyyMMddHHmmss"));
			data.Add("time_expire", DateTime.Now.AddMinutes(10).ToString("yyyyMMddHHmmss"));

			#region Debug

			//data.Add("time_start", "20200613130004");
			//data.Add("time_expire", "20200613131004");

			#endregion Debug

			data.Add("goods_tag", "");
			data.Add("trade_type", "JSAPI");

			data.Add("appid", "wx82fbe1be460a3cbf");
			data.Add("mch_id", _mchId);
			data.Add("spbill_create_ip", "8.8.8.8");
			data.Add("notify_url", "http://www.weixin.qq.com/wxpay/pay.php");

			string url = "https://api.mch.weixin.qq.com/pay/unifiedorder";
			//检测必填参数
			if (!data.ContainsKey("out_trade_no"))
			{
				throw new Exception("缺少统一支付接口必填参数out_trade_no！");
			}
			else if (!data.ContainsKey("body"))
			{
				throw new Exception("缺少统一支付接口必填参数body！");
			}
			else if (!data.ContainsKey("total_fee"))
			{
				throw new Exception("缺少统一支付接口必填参数total_fee！");
			}
			else if (!data.ContainsKey("trade_type"))
			{
				throw new Exception("缺少统一支付接口必填参数trade_type！");
			}

			//关联参数
			if (data["trade_type"].ToString() == "JSAPI" && !data.ContainsKey("openid"))
			{
				throw new Exception("统一支付接口中，缺少必填参数openid！trade_type为JSAPI时，openid为必填参数！");
			}
			if (data["trade_type"].ToString() == "NATIVE" && !data.ContainsKey("product_id"))
			{
				throw new Exception("统一支付接口中，缺少必填参数product_id！trade_type为JSAPI时，product_id为必填参数！");
			}

			data.Add("nonce_str", "5K8264ILTKCH16CQ2502SI8ZNMTM67VS"); //长度32位以内
			data.Add("sign_type", "HMAC-SHA256");//签名类型

			var sign = MakeUnifiedOrderSign(data);

			//签名
			data.Add("sign", sign);
			var xml = ToXml(data);

			var start = DateTime.Now;

			var client = new HttpClient();

			string response = SendUnifiedOrder(xml, url, false, 6);

			var end = DateTime.Now;

			int timeCost = (int)((end - start).TotalMilliseconds);

			// WxPayData result = new WxPayData();
			// result.FromXml(response);

			// ReportCostTime(url, timeCost, result);//测速上报

			// return result;
		}

		public static bool CheckValidationResult(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors)
		{
			//直接确认，否则打不开
			return true;
		}

		private string SendUnifiedOrder(string xml, string url, bool isUseCert, int timeout)
		{
			string result = "";//返回结果

			HttpWebRequest request = null;
			HttpWebResponse response = null;
			Stream reqStream = null;

			try
			{
				//设置最大连接数
				ServicePointManager.DefaultConnectionLimit = 200;
				//设置https验证方式
				if (url.StartsWith("https", StringComparison.OrdinalIgnoreCase))
				{
					ServicePointManager.ServerCertificateValidationCallback =
							new RemoteCertificateValidationCallback(CheckValidationResult);
				}

				/***************************************************************
                * 下面设置HttpWebRequest的相关属性
                * ************************************************************/
				request = (HttpWebRequest)WebRequest.Create(url);
				request.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36";
				request.Method = "POST";
				request.Timeout = timeout * 1000;

				//设置代理服务器
				//WebProxy proxy = new WebProxy();                          //定义一个网关对象
				//proxy.Address = new Uri(WxPayConfig.PROXY_URL);              //网关服务器端口:端口
				//request.Proxy = proxy;

				//设置POST的数据类型和长度
				request.ContentType = "text/xml";
				byte[] data = System.Text.Encoding.UTF8.GetBytes(xml);
				request.ContentLength = data.Length;

				//是否使用证书
				if (isUseCert)
				{
					request.ClientCertificates.Add(GetMerchantCertificate());
				}

				//往服务器写入数据
				reqStream = request.GetRequestStream();
				reqStream.Write(data, 0, data.Length);
				reqStream.Close();

				//获取服务端返回
				response = (HttpWebResponse)request.GetResponse();

				//获取服务端返回数据
				var sr = new StreamReader(response.GetResponseStream(), Encoding.UTF8);
				result = sr.ReadToEnd().Trim();
				sr.Close();
			}
			catch (System.Threading.ThreadAbortException e)
			{
				System.Threading.Thread.ResetAbort();
			}
			catch (WebException e)
			{
				if (e.Status == WebExceptionStatus.ProtocolError)
				{
				}
				throw new Exception(e.ToString());
			}
			catch (Exception e)
			{
				throw new Exception(e.ToString());
			}
			finally
			{
				//关闭连接和流
				response?.Close();
				request?.Abort();
			}
			return result;
		}

		private string ToXml(SortedDictionary<string, object> data)
		{
			//数据为空时不能转化为xml格式
			if (0 == data.Count)
			{
				//Log.Error(this.GetType().ToString(), "WxPayData数据为空!");
				throw new Exception("WxPayData数据为空!");
			}

			var xml = "<xml>";
			foreach (var pair in data)
			{
				//字段值不能为null，会影响后续流程
				if (pair.Value == null)
				{
					//Log.Error(this.GetType().ToString(), "WxPayData内部含有值为null的字段!");
					throw new Exception("WxPayData内部含有值为null的字段!");
				}

				if (pair.Value is int)
				{
					xml += "<" + pair.Key + ">" + pair.Value + "</" + pair.Key + ">";
				}
				else if (pair.Value is string)
				{
					xml += "<" + pair.Key + ">" + "<![CDATA[" + pair.Value + "]]></" + pair.Key + ">";
				}
				else//除了string和int类型不能含有其他数据类型
				{
					throw new Exception("WxPayData字段数据类型错误!");
				}
			}
			xml += "</xml>";
			return xml;
		}

		private string MakeUnifiedOrderSign(SortedDictionary<string, object> data)
		{
			if (!data.ContainsKey("sign_type"))
			{
				throw new Exception("签名类型未设置");
			}

			//转url格式
			var str = ToUrl(data);
			//在string后加入API KEY
			str += "&key=" + "66D54066affD50b5b20f257a8Db443a9"; // API密钥
			if (data["sign_type"].ToString() == "MD5")
			{
				var md5 = MD5.Create();
				var bs = md5.ComputeHash(Encoding.UTF8.GetBytes(str));
				var sb = new StringBuilder();
				foreach (var b in bs)
				{
					sb.Append(b.ToString("x2"));
				}
				//所有字符转为大写
				return sb.ToString().ToUpper();
			}
			else if (data["sign_type"].ToString() == "HMAC-SHA256")
			{
				return CalcHMACSHA256Hash(str, "66D54066affD50b5b20f257a8Db443a9");
			}
			else
			{
				throw new Exception("sign_type 不合法");
			}
		}

		private string CalcHMACSHA256Hash(string plaintext, string salt)
		{
			//var result = "";
			//var enc = Encoding.Default;
			//byte[]
			//	baText2BeHashed = enc.GetBytes(plaintext),
			//	baSalt = enc.GetBytes(salt);
			//var hasher = new HMACSHA256(baSalt);
			//var baHashedText = hasher.ComputeHash(baText2BeHashed);
			//result = string.Join("", baHashedText.ToList().Select(b => b.ToString("x2")).ToArray());
			//return result;

			var encoding = new System.Text.UTF8Encoding();
			var keyByte = encoding.GetBytes(salt);
			var messageBytes = encoding.GetBytes(plaintext);
			using var hmacsha256 = new HMACSHA256(keyByte);
			byte[] hashmessage = hmacsha256.ComputeHash(messageBytes);
			return string.Join("", hashmessage.ToList().Select(b => b.ToString("x2")).ToArray());
		}

		private string ToUrl(SortedDictionary<string, object> data)
		{
			var buff = "";
			foreach (var pair in data)
			{
				if (pair.Value == null)
				{
					throw new Exception("WxPayData内部含有值为null的字段!");
				}

				if (pair.Key != "sign" && pair.Value.ToString() != "")
				{
					buff += pair.Key + "=" + pair.Value + "&";
				}
			}
			buff = buff.Trim('&');
			return buff;
		}

		public async Task<string> JSAPI()
		{
			var data = new JSAPIRequestData()
			{
				sp_appid = _appId,
				sp_mchid = _mchId,
				sub_mchid = "1600105465",
				description = "Image形象店-深圳腾大-QQ公仔",
				out_trade_no = "X" + DateTime.Now.ToString("yyyyMMddHHmmss") + "0001",
				time_expire = DateTime.Now.AddMinutes(15).ToString("yyyy-MM-ddTHH:mm:ssK"),
				notify_url = "http://www.weixin.qq.com/wxpay/pay.php",
				settle_info = new JSAPISettleInfoRequestData()
				{
					profit_sharing = true,
				},
				amount = new JSAPIAmountRequestData()
				{
					total = 1,
					currency = "CNY",
				},
				payer = new JSAPIPlayerRequestData()
				{
					sp_openid = "oPFdmxF0Sk1YVYi_IWafv7MR3_pI",
				}
			};

			JsonSerializer _jsonWriter = new JsonSerializer
			{
				NullValueHandling = NullValueHandling.Ignore
			};

			var jsonContent = JsonConvert.SerializeObject(data, Formatting.None,
				new JsonSerializerSettings
				{
					NullValueHandling = NullValueHandling.Ignore
				});

			var httpHandler = new HttpHandler(_mchId, _serialNo, GetPublicCertificate().SerialNumber, GetPrivateCertificate(), GetMerchantCertificate(), jsonContent);
			var client = new HttpClient(httpHandler);

			var request = new HttpRequestMessage(HttpMethod.Post,
				"https://api.mch.weixin.qq.com/v3/pay/partner/transactions/jsapi")
			{
				Content = new StringContent(jsonContent, Encoding.UTF8, "application/json")
			};

			var response = await client.SendAsync(request);
			var result = await response.Content.ReadAsStringAsync();
			if (response.StatusCode != HttpStatusCode.OK)
			{
			}

			return string.Empty;
		}
	}
}