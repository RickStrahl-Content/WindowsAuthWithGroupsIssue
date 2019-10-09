using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace WindowsAuthenticationGroupsWithAutoLogonIssues
{
    public class Startup
    {
        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddAuthentication(NegotiateDefaults.AuthenticationScheme)
                .AddNegotiate();
            services.AddAuthorization();

        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();

            }

            app.UseRouting();


            // works
            app.UseAuthentication();
            app.UseAuthorization();

            // Pick up Windows Authentication
            app.Use(async (context, next) =>
            {

                // First off ensure that user is authenticated with NTLM Auth
                if (!context.User.Identity.IsAuthenticated)
                {
                    context.Response.StatusCode = 401;
                    context.Response.Headers.Add("www-authenticate",
                        new Microsoft.Extensions.Primitives.StringValues(new string[]
                        {
                            "Negotiate", "NTLM"
                        }));

                    await context.Response.WriteAsync("Unauthorized");
                    return;
                }
                
                await next();
 
            });


            app.UseEndpoints(endpoints =>
            {
                endpoints.MapGet("/", async context =>
                {
                    var identity = context.User.Identity as WindowsIdentity;

                    await context.Response.WriteAsync($"<pre>{PrintUserAndGroups(identity)}</pre>");
                });
            });
        }


        public static List<WindowsGroup> GetGroups(WindowsIdentity identity)
        {
            var groups = new List<WindowsGroup>();

            foreach (var group in identity.Groups)
            {
                var sid = group.Value;
                var groupName = GetGroupNameBySid(sid);
                var (username, domain) = SplitUserDomain(groupName);

                //if (groupName.StartsWith("NT AUTHORITY") ||
                //    groupName.StartsWith("BUILTIN") ||
                //    username == "Everyone" ||
                //    username == "None" ||
                //    username == "docker-users")

                //    continue;

                groups.Add(new WindowsGroup() { Name = username, Domain = domain, Sid = sid });
            }

            return groups;
        }


        public static string PrintUserAndGroups(WindowsIdentity identity)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("Identity Name: " + identity.Name);
            var groups = GetGroups(identity);
            foreach (var group in groups)
            {
                sb.AppendLine($"--- {group.Name}  {group.Domain}   {group.Sid}");
            }

            return sb.ToString();
        }




        /// <summary>
        /// Useful for converting WindowsIdentity Claims to
        /// actual names 
        /// </summary>
        /// <param name="sid"></param>
        /// <returns></returns>
        public static string GetGroupNameBySid(string sid)
        {
            try
            {
                return new SecurityIdentifier(sid).Translate(typeof(NTAccount)).ToString();
            }
            catch
            {
                return sid;
            }
        }

        public static (string, string) SplitUserDomain(string userAndDomain)
        {
            if (string.IsNullOrEmpty(userAndDomain))
                return (Environment.UserName, Environment.UserDomainName);

            string username;
            string domain;

            var tokens = userAndDomain.Split('/', '\\');
            if (tokens.Length == 1)
            {
                username = tokens[0];
                domain = Environment.UserDomainName;
            }
            else
            {
                domain = tokens[0];
                username = tokens[1];
            }

            return (username, domain);
        }

        [DebuggerDisplay("{Name} {Domain}  {Sid}")]
        public class WindowsGroup
        {
            public string Name { get; set; }
            public string Domain { get; set; }

            public string Sid { get; set; }
        }
    }
}
