using System.Threading.Tasks;

namespace APPBackstage.Services.WxMerchant
{
	public interface IWxPayService
	{
		/// <summary>
		/// 进件
		/// </summary>
		/// <returns></returns>
		Task<object> NewApplyMent();

		/// <summary>
		/// 认证
		/// </summary>
		/// <returns></returns>
		Task GetCertificates();

		/// <summary>
		/// 上传图片
		/// </summary>
		/// <param name="filename"></param>
		/// <param name="buffer"></param>
		/// <returns></returns>
		Task<string> Upload(string filename, byte[] buffer);
	}
}