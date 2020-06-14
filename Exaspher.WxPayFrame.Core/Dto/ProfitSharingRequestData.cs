namespace Exaspher.WxPayFrame.Core.Dto
{
	public class ProfitSharingRequestData
	{
		public string appid { get; set; }

		public string sub_mchid { get; set; }

		public string transaction_id { get; set; }

		public string out_order_no { get; set; }

		public ProfitSharingReceiverRequestData[] receivers { get; set; }

		public bool finish { get; set; }
	}

	public class ProfitSharingReceiverRequestData
	{
		public string type { get; set; }

		public string receiver_account { get; set; }

		public string receiver_mchid { get; set; }

		public int amount { get; set; }

		public string description { get; set; }
	}
}