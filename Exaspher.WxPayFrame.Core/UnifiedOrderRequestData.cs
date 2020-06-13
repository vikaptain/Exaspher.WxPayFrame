using System.Xml.Serialization;

namespace Exaspher.WxPayFrame.Core
{
	public class UnifiedOrderRequestData
	{
		[XmlElement("appid")]
		public string AppId { get; set; }

		[XmlElement("appid")]
		public string MchId { get; set; }

		[XmlElement("appid")]
		public string DeviceInfo { get; set; }

		[XmlElement("appid")]
		public string NonceStr { get; set; }

		[XmlElement("appid")]
		public string Sign { get; set; }

		[XmlElement("appid")]
		public string SignType { get; set; }

		[XmlElement("appid")]
		public string Body { get; set; }

		[XmlElement("appid")]
		public string Detail { get; set; }

		[XmlElement("appid")]
		public string Attach { get; set; }

		[XmlElement("appid")]
		public string OutTradeNo { get; set; }

		[XmlElement("appid")]
		public string FeeType { get; set; }

		[XmlElement("appid")]
		public string TotalFee { get; set; }

		[XmlElement("appid")]
		public string SpBillCreateIP { get; set; }

		[XmlElement("appid")]
		public string TimeStart { get; set; }

		[XmlElement("appid")]
		public string TimeExpire { get; set; }

		[XmlElement("appid")]
		public string GoodsTag { get; set; }

		[XmlElement("appid")]
		public string NotifyUrl { get; set; }

		[XmlElement("appid")]
		public string TradeType { get; set; }

		[XmlElement("appid")]
		public string ProductId { get; set; }

		public string LimitPay { get; set; }

		public string OpenId { get; set; }

		public string Receipt { get; set; }

		public UnifiedOrderSceneInfoRequestData SceneInfo { get; set; }
	}

	public class UnifiedOrderSceneInfoRequestData
	{
		public string Id { get; set; }

		public string Name { get; set; }

		public string AreaCode { get; set; }

		public string Address { get; set; }
	}
}