using System;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;

namespace Mopas.Tests
{
    /// <summary>
    /// 9.
    /// LADP Injection
    /// MOPAS
    /// Contains 1 vulnerability
    /// </summary>
    public partial class Ldap : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            var dc = new DirectoryContext(DirectoryContextType.Domain, "ptsecurity.ru");

            var address = Request.Params["address"];
            var filter = "Address=" + address;
            var result = "";

            var domain = Domain.GetDomain(dc);
			
            // this is our vulnerabilitiy of LDAP injection *in this file*
            var ds = new DirectorySearcher(domain.GetDirectoryEntry()); // No variable - no problem!

			// Let's go!

            // VERIFY: AI issue #5, High, LDAP, http://omachalov.ptsecurity.ru/#/taskResults/5
            // GET /Tests/1%20INPUT%20DATA%20VERIFICATION/9%20LDAP%20Injection/Ldap.aspx.cs?address=* HTTP/1.1
            // Host: localhost
            using (var src = ds.FindAll())
            {
                foreach (var res in src)
                {
                    result = res.ToString();
                }
            }

            var name = Request.Params["name"];

            // this is our first vulnerability of XSS in this file
            // we will demonstrate False Positive scenario here (FP Marker)
            // FP: AI issue #11, Medium, XSS, http://omachalov.ptsecurity.ru/#/taskResults/9
            // GET /Tests/1%20INPUT%20DATA%20VERIFICATION/9%20LDAP%20Injection/Ldap.aspx.cs?name=%3cscript%3ealert(1)%3c%2fscript%3e HTTP/1.1
            // Host: localhost
            Response.Write(name);

            // this is our second vulnerability of XSS in this file
            // we will demonstrate what happen if developer fails with his fix (VERIFY Marker)
            // FIXED: AI issue #12, Medium, XSS, http://omachalov.ptsecurity.ru/#/taskResults/7
            // GET /Tests/1%20INPUT%20DATA%20VERIFICATION/9%20LDAP%20Injection/Ldap.aspx.cs?name=%3cscript%3ealert(1)%3c%2fscript%3e HTTP/1.1
            // Host: localhost
            Response.Write("name"); // No fix

            // this is our third vulnerability of XSS in this file
            // we will demonstrate what happen if we really fix vulnerability (VERIFY Marker)
	    // FIXED: AI issue #13, Medium, XSS, http://omachalov.ptsecurity.ru/#/taskResults/2
	    // GET /Tests/1%20INPUT%20DATA%20VERIFICATION/9%20LDAP%20Injection/Ldap.aspx.cs?name=%3cscript%3ealert(1)%3c%2fscript%3e HTTP/1.1
	    // Host: localhost
	    Response.Write("name");

            // this is our fourth vulnerability of XSS in this file
            // we will demonstrate what happen if developer want to cheat (FIXED Marker)
            // FIXED: AI issue #14, Medium, XSS, http://omachalov.ptsecurity.ru/#/taskResults/6
            // GET /Tests/1%20INPUT%20DATA%20VERIFICATION/9%20LDAP%20Injection/Ldap.aspx.cs?name=%3cscript%3ealert(1)%3c%2fscript%3e HTTP/1.1
            // Host: localhost
            Response.Write("name");
        }
    }
}
