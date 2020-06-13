using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using APPBackstage.Services.WxMerchant;

namespace Exaspher.WxPayFrame.Core
{
    public class HttpHandler : DelegatingHandler
    {
        private readonly string _json;
        private readonly X509Certificate2 _merchantCertificate;
        private readonly string _platformSerialNo;

        /// <summary>
        /// 构造方法
        /// </summary>
        /// <param name="platformSerialNo"></param>
        /// <param name="privateKey"> 私钥不包括私钥文件起始的-----BEGIN PRIVATE KEY-----        亦不包括结尾的-----END PRIVATE KEY-----</param>
        /// <param name="merchantCertificate"></param>
        /// <param name="certPassword"></param>
        /// <param name="json">签名json数据,默认不需要传入，获取body内容，如传入签名传入参数上传图片时需传入</param>
        public HttpHandler(string platformSerialNo, X509Certificate2 merchantCertificate, string json = default(string))
        {
            var handler = new HttpClientHandler
            {
                ClientCertificateOptions = ClientCertificateOption.Manual,
                SslProtocols = SslProtocols.Tls12
            };
            try
            {
                handler.ClientCertificates.Add(merchantCertificate);
            }
            catch (Exception e)
            {
                throw new Exception("ca err(证书错误)");
            }
            handler.SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls11 | SslProtocols.Tls;
            handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true;
            InnerHandler = handler;
            _json = json;
            _merchantCertificate = merchantCertificate;
            _platformSerialNo = platformSerialNo;
        }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var auth = await BuildAuthAsync(request);
            request.Headers.Add("Authorization", $"WECHATPAY2-SHA256-RSA2048 {auth}");
            request.Headers.Add("Wechatpay-Serial", _platformSerialNo);
            request.Headers.Add("user-agent", "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.143 Safari/537.36");
            MediaTypeWithQualityHeaderValue mediaTypeWithQualityHeader = new MediaTypeWithQualityHeaderValue("application/json");
            request.Headers.Accept.Add(mediaTypeWithQualityHeader);
            request.Headers.AcceptCharset.Add(new StringWithQualityHeaderValue("utf-8"));
            return await base.SendAsync(request, cancellationToken);
        }

        protected async Task<string> BuildAuthAsync(HttpRequestMessage request)
        {
            var method = request.Method.ToString();
            var body = "";
            if (method == "POST" || method == "PUT" || method == "PATCH")
            {
                if (!string.IsNullOrEmpty(_json))
                {
                    body = _json;
                }
                else
                {
                    var content = request.Content;
                    body = await content.ReadAsStringAsync();
                }
            }
            var uri = request.RequestUri.PathAndQuery;
            var timestamp = DateTimeOffset.Now.ToUnixTimeSeconds();
            var nonce = Guid.NewGuid().ToString("n");
            var message = $"{method}\n{uri}\n{timestamp}\n{nonce}\n{body}\n";

            var signature = Sign(message);

            return $"mchid=\"{WxConfig.MchId}\",nonce_str=\"{nonce}\",timestamp=\"{timestamp}\",serial_no=\"{WxConfig.SerialNo}\",signature=\"{signature}\"";
        }

        protected string Sign(string message)
        {
            // using var cngKey = CngKey.Import(Convert.FromBase64String(), CngKeyBlobFormat.Pkcs8PrivateBlob);

            //byte[] keyData = Convert.FromBase64String(privateKey);
            //using (CngKey cngKey = CngKey.Import(keyData, CngKeyBlobFormat.Pkcs8PrivateBlob))
            //using (RSACng rsa = new RSACng(cngKey))
            //{
            //	byte[] data = System.Text.Encoding.UTF8.GetBytes(message);
            //	return Convert.ToBase64String(rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
            //}

            //var data = System.Text.Encoding.UTF8.GetBytes(message);
            //return Convert.ToBase64String(_privateKey.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));

            // string privateKey = "{你的私钥}";
            byte[] keyData = Convert.FromBase64String(WxConfig.PrivateKey);
            try
            {
                using (CngKey cngKey = CngKey.Import(keyData, CngKeyBlobFormat.Pkcs8PrivateBlob))
                {
                    using (RSACng rsa = new RSACng(cngKey))
                    {
                        byte[] data = System.Text.Encoding.UTF8.GetBytes(message);
                        return Convert.ToBase64String(rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
                    }
                }
            }catch(Exception exp)
            {
                // LogHelper.WriteLog(exp);
                return string.Empty;
            }

            //using var rsa = new RSACng(cngKey);

            //var data = System.Text.Encoding.UTF8.GetBytes(message);
            //return Convert.ToBase64String(rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        }
    }
}