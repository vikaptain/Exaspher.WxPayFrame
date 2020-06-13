using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Exaspher.WxPayFrame.Core.Dto
{
	public class JSAPIRequestData
	{
		public string sp_appid { get; set; }

		public string sp_mchid { get; set; }

		public string sub_appid { get; set; }

		public string sub_mchid { get; set; }

		public string description { get; set; }

		public string out_trade_no { get; set; }

		public string time_expire { get; set; }

		public string attach { get; set; }

		public string notify_url { get; set; }

		public string goods_tag { get; set; }

		public JSAPISettleInfoRequestData settle_info { get; set; }

		public JSAPIAmountRequestData amount { get; set; }

		public JSAPIPlayerRequestData payer { get; set; }

		public JSAPIDetailRequestData detail { get; set; }

		public JSAPIGoodsDetailRequestData goods_detail { get; set; }

		public JSAPISceneInfoRequestData scene_info { get; set; }
	}

	public class JSAPISettleInfoRequestData
	{
		public bool profit_sharing { get; set; }

		public int subsidy_amount { get; set; }
	}

	public class JSAPIAmountRequestData
	{
		public int total { get; set; }

		public string currency { get; set; }
	}

	public class JSAPIPlayerRequestData
	{
		public string sp_openid { get; set; }

		public string sub_openid { get; set; }
	}

	public class JSAPIDetailRequestData
	{
		public string cost_price { get; set; }

		public string invoice_id { get; set; }
	}

	public class JSAPIGoodsDetailRequestData
	{
		public string merchant_goods_id { get; set; }

		public string wechatpay_goods_id { get; set; }

		public string goods_name { get; set; }

		public int quantity { get; set; }

		public int unit_price { get; set; }
	}

	public class JSAPISceneInfoRequestData
	{
		public string payer_client_ip { get; set; }
		public string device_id { get; set; }

		public  JSAPIStoreInfoRequestData store_info { get; set; }
	}

	public class JSAPIStoreInfoRequestData
	{
		public string id { get; set; }

		public string name { get; set; }

		public string area_code { get; set; }

		public string address { get; set; }
	}
}


