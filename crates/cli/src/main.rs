use std::io::{self, Write};
use std::time::Duration;
use steam_core::{
    EAuthSessionGuardType, EAuthTokenPlatformType, LoginSession, PollStatus,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=====================================================");
    println!("             Steam Auth CLI (steam-login)            ");
    println!("=====================================================\n");

    let args: Vec<String> = std::env::args().collect();
    let (username, password) = if args.len() >= 3 {
        (args[1].clone(), args[2].clone())
    } else {
        print!("Ingresa tu usuario de Steam: ");
        io::stdout().flush()?;
        let mut user_input = String::new();
        io::stdin().read_line(&mut user_input)?;
        let user = user_input.trim().to_string();

        print!("Ingresa tu contraseña de Steam (no se mostrará): ");
        io::stdout().flush()?;
        let pass = rpassword::read_password()?;
        (user, pass)
    };

    if username.is_empty() || password.is_empty() {
        eprintln!("Usuario o contraseña vacíos. Abortando.");
        return Ok(());
    }

    println!("\n[1/4] Conectando con Steam y cifrando credenciales con RSA...");
    let mut session = LoginSession::new(EAuthTokenPlatformType::WebBrowser);

    let auth_info = match session.start_with_credentials(&username, &password).await {
        Ok(info) => info,
        Err(e) => {
            eprintln!("❌ Error al iniciar sesión: {e}");
            return Ok(());
        }
    };

    println!("   Sesión iniciada en Steam!");
    println!("   - Client ID: {}", auth_info.client_id);
    if auth_info.steam_id != 0 {
        println!("   - Steam ID: {}", auth_info.steam_id);
    }
    println!("   - Métodos de confirmación permitidos: {:?}", auth_info.allowed_confirmations);

    // 2. Verificar el método de confirmación
    let has_mobile_confirmation = auth_info
        .allowed_confirmations
        .contains(&EAuthSessionGuardType::DeviceConfirmation);
    let has_device_code = auth_info
        .allowed_confirmations
        .contains(&EAuthSessionGuardType::DeviceCode);
    let has_email_code = auth_info
        .allowed_confirmations
        .contains(&EAuthSessionGuardType::EmailCode);

    if has_mobile_confirmation {
        println!("\n[2/4] 📱 ¡NOTIFICACIÓN ENVIADA A TU APP MÓVIL DE STEAM!");
        println!("   Abre tu teléfono, ve a las notificaciones o a Steam Mobile y presiona 'APROBAR'.");
        println!("   Esperando tu confirmación...");
    } else if has_device_code || has_email_code {
        println!("\n[2/4] Código de Steam Guard requerido.");
        let prompt = if has_email_code {
            "Ingresa el código que te llegó al correo: "
        } else {
            "Ingresa el código de 5 dígitos de tu Steam Mobile Authenticator: "
        };
        print!("{}", prompt);
        io::stdout().flush()?;
        let mut code_input = String::new();
        io::stdin().read_line(&mut code_input)?;
        let code = code_input.trim();

        let guard_type = if has_email_code {
            EAuthSessionGuardType::EmailCode
        } else {
            EAuthSessionGuardType::DeviceCode
        };

        println!("   Enviando código a Steam...");
        session.submit_steam_guard_code(code, guard_type).await?;
        println!("   Código enviado. Verificando...");
    }

    // 3. Sondeo (Polling) hasta que el usuario apruebe en el teléfono o se confirme el código
    let poll_interval = if auth_info.interval < 1.0 { 3.0 } else { auth_info.interval };
    println!("\n[3/4] Comprobando estado de la sesión (polling cada {}s)...", poll_interval);

    let max_timeout = Duration::from_secs(120);
    let start_time = std::time::Instant::now();
    let mut tokens = None;

    while start_time.elapsed() < max_timeout {
        print!(".");
        io::stdout().flush()?;

        match session.poll_status().await {
            Ok(PollStatus::Confirmed(t)) => {
                tokens = Some(t);
                break;
            }
            Ok(PollStatus::Waiting) => {
                tokio::time::sleep(Duration::from_secs_f32(poll_interval)).await;
            }
            Err(e) => {
                println!("\n❌ Error en el sondeo: {e}");
                return Ok(());
            }
        }
    }

    println!();
    let auth_tokens = match tokens {
        Some(t) => t,
        None => {
            eprintln!("❌ Tiempo de espera agotado sin confirmación.");
            return Ok(());
        }
    };

    println!("\n🎉 ¡AUTENTICACIÓN CONFIRMADA CON ÉXITO!");
    println!("   - Cuenta: {}", auth_tokens.account_name);
    println!("   - Refresh Token: {}...", &auth_tokens.refresh_token[..auth_tokens.refresh_token.len().min(35)]);

    // 4. Obtener las Cookies Web (steamLoginSecure y sessionid)
    println!("\n[4/4] Obteniendo cookies de sesión web (/jwt/finalizelogin)...");
    match session.get_web_cookies().await {
        Ok(cookies) => {
            println!("\n=====================================================");
            println!("             ¡COOKIES WEB OBTENIDAS!                 ");
            println!("=====================================================");
            println!("sessionid        : {}", cookies.session_id);
            if let Some(secure) = cookies.steam_login_secure {
                println!("steamLoginSecure : {}", secure);
            }
            println!("Total cookies    : {}", cookies.all_cookies.len());
            println!("-----------------------------------------------------");
            println!("Todas las cookies recolectadas:");
            for c in cookies.all_cookies {
                println!("  * {}", c);
            }
            println!("=====================================================");
            println!("Tu sesión web está lista para consultar APIs o la web de Steam.");
        }
        Err(e) => {
            eprintln!("❌ Error obteniendo cookies web: {e}");
        }
    }

    Ok(())
}
