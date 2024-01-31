use actix_web::{web, App, HttpServer, HttpRequest, HttpResponse};
use dotenv::dotenv;
use serde::Deserialize;
use serde_json::Value;
use url::Url;

#[derive(Debug, Deserialize)]
struct GoogleTokenResponse {
    access_token: String,
    token_type: String,
    expires_in: i64,
    refresh_token: Option<String>,
    id_token: String,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();

    HttpServer::new(|| {
        App::new()
            .service(web::resource("/login").route(web::get().to(login)))
            .service(web::resource("/callback").route(web::get().to(callback)))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}

async fn login() -> HttpResponse {
    let google_auth_url = format!(
        "https://accounts.google.com/o/oauth2/auth?client_id={}&redirect_uri={}&response_type=code&scope=email%20profile",
        dotenv::var("GOOGLE_CLIENT_ID").unwrap(),
        "http://localhost:8080/callback"
    );

    HttpResponse::Found()
        .header("location", google_auth_url)
        .finish()
}

async fn callback(req: HttpRequest) -> HttpResponse {
    if let Some(code) = req.uri().query() {
        let code_value = Url::parse(&format!("http://localhost:8080/callback?{}", code))
            .ok()
            .and_then(|url| {
                url.query_pairs()
                    .find(|(key, _)| key == "code")
                    .map(|(_, value)| value.to_string())
            });

        if let Some(code) = code_value {
            let client_id = dotenv::var("GOOGLE_CLIENT_ID").unwrap();
            let client_secret = dotenv::var("GOOGLE_CLIENT_SECRET").unwrap();

            let token_url = "https://oauth2.googleapis.com/token";
            let token_params = [
                ("code", &code),
                ("client_id", &client_id),
                ("client_secret", &client_secret),
                ("redirect_uri", &"http://localhost:8080/callback".to_string()),
                ("grant_type", &"authorization_code".to_string()),
            ];

            let client = reqwest::Client::new();
            let token_response: Result<GoogleTokenResponse, reqwest::Error> = match client
                .post(token_url)
                .form(&token_params)
                .send()
                .await
            {
                Ok(response) => match response.json::<GoogleTokenResponse>().await {
                    Ok(token) => Ok(token),
                    Err(err) => {
                        println!("Failed to parse token response: {:?}", err);
                        Err(err)
                    } 
                },
                Err(err) => {
                    println!("Failed to send token request: {:?}", err);
                    Err(err)
                }
            };

            match token_response {
                Ok(response) => {
                    let access_token = response.access_token;

                    let user_info_url =
                        "https://people.googleapis.com/v1/people/me?personFields=emailAddresses,names";
                    let user_info_response: Result<Value, reqwest::Error> = match client
                        .get(user_info_url)
                        .header("Authorization", format!("Bearer {}", access_token))
                        .send()
                        .await
                    {
                        Ok(response) => match response.json::<Value>().await {
                            Ok(info) => Ok(info),
                            Err(err) => {
                                println!("Failed to parse user info response: {:?}", err);
                                Err(err)
                            }
                        },
                        Err(err) => {
                            println!("Failed to send user info request: {:?}", err);
                            Err(err)
                        }
                    };

                    match user_info_response {
                        Ok(user_info) => {
                            println!("User Info Response: {:?}", user_info);

                            let user_name = user_info["names"][0]["displayName"]
                                .as_str()
                                .unwrap_or_default();
                            let user_email = user_info["emailAddresses"][0]["value"]
                                .as_str()
                                .unwrap_or_default();
                            println!("User Code: {}", code);
                            println!("User Name: {}", user_name);
                            println!("User Email: {}", user_email);

                            HttpResponse::Ok().body(format!(
                                "Received 'code': {},\nUser Name: {},\nUser Email: {}",
                                code, user_name, user_email
                            ))
                        }
                        Err(err) => HttpResponse::InternalServerError()
                            .body(format!("Failed to fetch user info: {:?}", err)),
                    }
                }
                Err(err) => HttpResponse::InternalServerError()
                    .body(format!("Failed to obtain access token: {:?}", err)),
            }
        } else {
            return HttpResponse::BadRequest().body("Invalid 'code' parameter in the callback URL");
        }
    } else {
        return HttpResponse::BadRequest().body("No query parameters in the callback URL");
    }
}