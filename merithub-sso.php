<?php
/*
Plugin Name: MeritHub SSO Integration
Description: Single Sign-On (SSO) integration with MeritHub using JWT authentication.
Version: 1.0
Author: Francesco Fera
*/


function merithub_sso_button_shortcode($atts) {
    $atts = shortcode_atts(array(
        'type' => 'button', 
        'text' => 'Access Sessions', 
    ), $atts);

    $current_user_id = (string) get_current_user_id();

    $secret = MH_ENCRYPTION_KEY;

    $token_generated = generate_jwt_token($secret, $current_user_id);

    $encoded_user_info = base64url_encode($token_generated);

    // Prepare the URL for redirection
    $redirect_url = 'https://merithub.com/sso/c6qt82qckrg1fb7vf1k0?token=' . $encoded_user_info;

    // Prepare the HTML based on display type
    if ($atts['type'] === 'button') {
        $html = '<a id="merithub-sso-button" href="' . esc_url($redirect_url) . '">' . esc_attr($atts['text']) . '</a>';
    } elseif ($atts['type'] === 'link') {
        $html = '<a href="' . esc_url($redirect_url) . '">' . esc_attr($atts['text']) . '</a>';
    } else {
        $html = ''; // Invalid display type
    }

    return $html;
}
add_shortcode('merithub_sso_button', 'merithub_sso_button_shortcode');


// Register merithub endpoints

function register_merithub_get_endpoint() {
    register_rest_route( 'custom/v1', '/merithub-user-data', array(
        'methods' => 'GET',
        'callback' => 'get_user_data_for_merithub',
    ) );
}
add_action( 'rest_api_init', 'register_merithub_get_endpoint' );

// CALLBACKS

function get_user_data_for_merithub( $request ) {
    $token_url = getBearerToken($request);
    $token = base64url_decode($token_url);

    $secret = MH_ENCRYPTION_KEY;
    
    // Check if JWT token is valid
    $payload = is_jwt_valid($token, $secret);

    if (!$payload) {
        $error_msg = 'Invalid JWT token.';
        $error_details = array(
            'request' => $request->get_headers(),
            'token' => $token,
            'payload' => $payload
        );
        return new WP_Error( 'invalid_token', $error_msg, array( 'status' => 401, 'details' => $error_details ) );
    }
    
    //getting user data
    $json_payload = json_decode($payload);
    $user_id = $json_payload->user_id;

    if ( empty( $user_id ) ) {
        return new WP_Error( 'missing_user_id', 'Missing user ID.', array( 'status' => 400 ) );
    }

    $user = get_user_by( 'ID', $user_id );

    if ( ! $user ) {
        return new WP_Error( 'user_not_found', 'User not found.', array( 'status' => 404 ) );
    }

    $user_data = array(
        'name' => $user->display_name,
        'email' => $user->user_email,
        'mobileNumber' => get_user_meta( $user_id, 'mobile_number', true ),
        'country' => get_user_meta( $user_id, 'country', true ),
        'countryCode' => get_user_meta( $user_id, 'country_code', true ),
        'id' => str_pad($user_id, 6, '0', STR_PAD_LEFT), // Ensure at least 6 chars
        //'role' => $user->roles[0],
        'tz' => get_user_meta( $user_id, 'timezone', true ),
        'permission' => get_user_meta( $user_id, 'permission', true ),
        'img' => get_user_meta( $user_id, 'profile_image', true ),
        'redirectUrl' => get_user_meta( $user_id, 'redirect_url', true ),
        'credits' => get_user_meta( $user_id, 'credits', true ),
        'update' => false,
        'classes' => get_user_meta( $user_id, 'class_ids', true ),
        'courses' => get_user_meta( $user_id, 'course_data', true ),
        'services' => get_user_meta( $user_id, 'service_ids', true ),
    );

    return $user_data;
}

// HELPERS
function getAuthorizationHeader(){
    $headers = null;
    if (isset($_SERVER['Authorization'])) {
        $headers = trim($_SERVER["Authorization"]);
    } else if (isset($_SERVER['HTTP_AUTHORIZATION'])) { 
    //Nginx or fast CGI
        $headers = trim($_SERVER["HTTP_AUTHORIZATION"]);
    } elseif (function_exists('apache_request_headers')) {
        $requestHeaders = apache_request_headers();
        // Server-side fix for bug in old Android versions (a nice side-effect of this fix means we don't care about capitalization for Authorization)
        $requestHeaders = array_combine(array_map('ucwords', array_keys($requestHeaders)), array_values($requestHeaders));
        //print_r($requestHeaders);
        if (isset($requestHeaders['Authorization'])) {
            $headers = trim($requestHeaders['Authorization']);
        }
    }
    return $headers;
}

function getBearerToken() {
    $headers = getAuthorizationHeader();
    // HEADER: Get the access token from the header
    if (!empty($headers)) {
        if (preg_match('/Bearer\s(\S+)/', $headers, $matches)) {
            return $matches[1];
        }
    }
    return null;
}
//BACK TO 3600
function generate_jwt_token($secret, $user_id, $expiration = 6000) {
    $header = json_encode(['alg' => 'HS256', 'typ' => 'JWT']);
    $payload = json_encode(['user_id' => $user_id, 'exp' => time() + $expiration]);

    $header = base64url_encode($header);
    $payload = base64url_encode($payload);

    $signature = hash_hmac('sha256', "$header.$payload", $secret, true);
    $signature = base64url_encode($signature);

    return "$header.$payload.$signature";
}


function is_jwt_valid($jwt, $secret) {
    // split the jwt
    $tokenParts = explode('.', $jwt);
    $header = base64url_decode($tokenParts[0]);
    $payload = base64url_decode($tokenParts[1]);
    $signature_provided = base64url_decode($tokenParts[2]);

    // build a signature based on the header and payload using the secret
    $base64_url_header = base64url_encode($header);
    $base64_url_payload = base64url_encode($payload);
    $signature = hash_hmac('SHA256', $base64_url_header . "." . $base64_url_payload, $secret, true);
    $base64_url_signature = base64url_encode($signature);

    // verify it matches the signature provided in the jwt
    $is_signature_valid = ($signature == $signature_provided);

    if (!$is_signature_valid) {
        return FALSE;
    } 

    // check the expiration time - note this will cause an error if there is no 'exp' claim in the jwt
    $expiration = json_decode($payload)->exp;
    $is_token_expired = ($expiration - time()) < 0;

    if ($is_token_expired) {
        return FALSE;
    } else {
        return $payload;
    }
}

function base64url_encode($data) {
    $b64 = base64_encode($data);
    if ($b64 === false) {
        return false;
    }
    $url = strtr($b64, '+/', '-_');
    return rtrim($url, '=');
}

function base64url_decode($data, $strict = false)
{
    // Convert Base64URL to Base64 by replacing “-” with “+” and “_” with “/”
    $b64 = strtr($data, '-_', '+/');

    // Decode Base64 string and return the original data
    return base64_decode($b64, $strict);
}