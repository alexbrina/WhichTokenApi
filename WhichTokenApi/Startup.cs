using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Text;
using System.Threading.Tasks;

namespace WhichTokenApi
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services)
        {
            var secret = Configuration.GetValue<string>("Secret");

            services.AddSingleton(new Jwt(
                secret,
                Configuration.GetValue<string>("ECDsaCertificateFileName")));

            services.AddAuthentication()
                .AddJwtBearer("Regular", options =>
                {
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ClockSkew = TokenValidationParameters.DefaultClockSkew,
                        ValidateAudience = true,
                        ValidateIssuer = true,
                        ValidateIssuerSigningKey = true,
                        ValidIssuer = "WhichTokenApi",
                        ValidAudience = "WhichTokenApiRegularClient",
                        ValidateLifetime = true,
                        IssuerSigningKey = new SymmetricSecurityKey(
                            Encoding.UTF8.GetBytes(secret))
                    };
                })
                .AddJwtBearer("Alternative", options =>
                {
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ClockSkew = TokenValidationParameters.DefaultClockSkew,
                        ValidateAudience = true,
                        ValidateIssuer = true,
                        ValidateIssuerSigningKey = true,
                        ValidIssuer = "WhichTokenApi",
                        ValidAudience = "WhichTokenApiAlternativeClient",
                        ValidateLifetime = true,
                        IssuerSigningKey = new SymmetricSecurityKey(
                            Encoding.UTF8.GetBytes(secret))
                    };
                });

            // now we need to determine the authorization policies by hand
            // notice that there is one default policy
            services.AddAuthorization(options =>
                {
                    options.DefaultPolicy = new AuthorizationPolicyBuilder()
                        .RequireAuthenticatedUser()
                        .AddAuthenticationSchemes("Regular")
                        .Build();

                    options.AddPolicy("Alternative", new AuthorizationPolicyBuilder()
                        .RequireAuthenticatedUser()
                        .AddAuthenticationSchemes("Alternative")
                        .Build());
                });

            services.AddControllers();
            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo { Title = "WhichTokenApi", Version = "v1" });

                c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
                {
                    In = ParameterLocation.Header,
                    Name = "Authorization",
                    Scheme = JwtBearerDefaults.AuthenticationScheme,
                    Type = SecuritySchemeType.Http,
                    BearerFormat = "JWT",
                    Description = "JWT Authorization header using the Bearer scheme."
                });

                c.AddSecurityRequirement(new OpenApiSecurityRequirement
                {
                    {
                        new OpenApiSecurityScheme
                        {
                            Reference = new OpenApiReference
                            {
                                Type = ReferenceType.SecurityScheme,
                                Id = "Bearer"
                            }
                        },
                        new string[] {}
                    }
                });
            });
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseSwagger();
                app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "WhichTokenApi v1"));
            }

            app.UseRouting();

            // the UseAuthentication() middleware will call context.AuthenticateAsync(...)
            // and populate context.User, without this, requests will always return Unauthorized
            // when they reach the UseAuthorization() middleware

            // curiously, this will only authenticate when some endpoint with the
            // Authorize attribute will run (I guess it's determined in UseRouting()).
            // And if you remove UseAuthorization() authentication never happens
            app.UseAuthentication();

            // by checking context.User in various points you can check is auth status
            app.Use(async (context, next) =>
            {
                var data = GetUserData(context, "", "Entering: Between UseAuthentication() and UseAuthorization()");

                await next();

                data = GetUserData(context, data, "Returning: Between UseAuthentication() and UseAuthorization()");
                await ResponseWrite(context, data);
            });

            app.UseAuthorization();

            app.Use(async (context, next) =>
            {
                var data = GetUserData(context, "", "Entering: After UseAuthorization()");

                await next();

                data = GetUserData(context, data, "Returning: After UseAuthorization()");
                await ResponseWrite(context, data);
            });

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }

        private static string GetUserData(HttpContext context, string data, string step)
        {
            data += $"\n\n{step}: IsAuthenticated = {context.User.Identity.IsAuthenticated}";
            return data;
        }

        private static ValueTask ResponseWrite(HttpContext context, string data)
        {
            var bytes = Encoding.UTF8.GetBytes(data);
            return context.Response.Body.WriteAsync(bytes);
        }
    }
}
