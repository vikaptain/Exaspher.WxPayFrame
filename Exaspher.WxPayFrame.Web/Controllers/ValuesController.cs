﻿using Exaspher.WxPay.Core;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Web.Http;

namespace Exaspher.WxPayFrame.Web.Controllers
{
	public class ValuesController : ApiController
	{
		// GET api/values
		public IEnumerable<string> Get()
		{
			return new string[] { "value1", "value2" };
		}

		// GET api/values/5
		public async Task<string> Get(int id)
		{
			WxPayService service = new WxPayService();
			await service.ProfitSharing();
			return "value";
		}

		// POST api/values
		public void Post([FromBody] string value)
		{
		}

		// PUT api/values/5
		public void Put(int id, [FromBody] string value)
		{
		}

		// DELETE api/values/5
		public void Delete(int id)
		{
		}
	}
}