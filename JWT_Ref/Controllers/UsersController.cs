using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace JWT_Ref.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
   
    public class UsersController : ControllerBase
    {

        [HttpGet]
        [Authorize]
        [Route("directory")]
        public IActionResult Get()
        {
            return Ok();
        }

        [HttpGet]
        [Route("details/{id}")]
        public IActionResult GetDetails(int  id)
        {
            return Ok();
        }
    }
}
