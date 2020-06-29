using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using EmployeeManagement.Models;
using EmployeeManagement.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.CodeAnalysis.Options;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace EmployeeManagement
{
    public class Startup
    {
        private IConfiguration _config;

        public Startup(IConfiguration config)
        {
            _config = config;
        }
        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddDbContextPool<AppDbContext>(options => options.UseSqlServer(_config.GetConnectionString("EmployeeDBConnection")));

            services.AddIdentity<ApplicationUser, IdentityRole>(options =>
            {
                options.Password.RequiredLength = 10;
                options.Password.RequiredUniqueChars = 3;

                options.SignIn.RequireConfirmedEmail = true;

                options.Tokens.EmailConfirmationTokenProvider = "CustomEmailConfirmation";

                options.Lockout.MaxFailedAccessAttempts = 5;
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
            })
            .AddEntityFrameworkStores<AppDbContext>()
            .AddDefaultTokenProviders()
            .AddTokenProvider<CustomEmailConfirmationTokenProvider<ApplicationUser>>("CustomEmailConfirmation");

            services.Configure<DataProtectionTokenProviderOptions>(options => options.TokenLifespan = TimeSpan.FromHours(5));

            services.Configure<CustomEmailConfirmationTokenProviderOptions>(options => options.TokenLifespan = TimeSpan.FromDays(3));

            services.AddMvc(options =>
            {
                var policy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();
                options.Filters.Add(new AuthorizeFilter(policy));
                options.EnableEndpointRouting = false;
            }).AddXmlSerializerFormatters();

            services.AddAuthentication()
                .AddGoogle(options =>
                {
                options.ClientId = "365266985178-fnqp1o7h6q8fc0i598cu2ugl5kbhjhs8.apps.googleusercontent.com";
                options.ClientSecret = "FjjdrfA5QlzDbJhsjDF0_n3b";
                }).AddFacebook(options =>
                {
                    options.AppId = "2665217160465389";
                    options.AppSecret = "e4a5cf13ada0069ec81ca82916cd51f3";
                });

            services.ConfigureApplicationCookie(options =>
            {
                options.AccessDeniedPath = new PathString("/Administration/AccessDenied");
            });

            services.AddAuthorization(options =>
            {
                options.AddPolicy("DeleteRolePolicy",
                    policy => policy.RequireAssertion(context =>
                        context.User.IsInRole("Admin") &&
                        context.User.HasClaim(claim =>
                            claim.Type == "Edit Role" &&
                            claim.Value == "true") ||
                        context.User.IsInRole("Super Admin")
                    )
                );

                options.AddPolicy("EditRolePolicy", policy => 
                    policy.AddRequirements(new ManageAdminRolesAndClaimsRequirement()));

                //claims are preferred over roles
                options.AddPolicy("AdminRolePolicy",
                    policy => policy.RequireRole("Admin"));
            });
            services.AddScoped<IEmployeeRepository, SQLEmployeeRepository>();

            services.AddSingleton<IAuthorizationHandler, CanEditOnlyOtherAdminRolesAndClaimsHandler>();
            services.AddSingleton<IAuthorizationHandler, SuperAdminHandler>();

            services.AddSingleton<DataProtectionPurposeStrings>();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                /*DeveloperExceptionPageOptions developerExceptionPageOptions = new DeveloperExceptionPageOptions(){
                    SourceCodeLineCount = 10
                };*/
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Error");
                app.UseStatusCodePagesWithReExecute("/Error/{0}");
            }

            /*FileServerOptions fileServerOptions = new FileServerOptions();
            fileServerOptions.DefaultFilesOptions.DefaultFileNames.Clear();
            fileServerOptions.DefaultFilesOptions.DefaultFileNames.Add("foo.html");*/

            app.UseStaticFiles();
            //app.UseMvcWithDefaultRoute();
            app.UseAuthentication();

            app.UseMvc(routes =>
            {
                routes.MapRoute("default", "{controller=Home}/{action=Index}/{id?}");
            });

            /*DefaultFilesOptions defaultFilesOptions = new DefaultFilesOptions();
            defaultFilesOptions.DefaultFileNames.Clear();
            defaultFilesOptions.DefaultFileNames.Add("foo.html");
            app.UseDefaultFiles(defaultFilesOptions);
            app.UseStaticFiles();*/

            app.UseRouting();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapGet("/", async context =>
                {
                    await context.Response.WriteAsync("Hello World!");
                });
            });
        }
    }
}
