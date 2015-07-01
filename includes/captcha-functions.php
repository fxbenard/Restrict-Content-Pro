<?php


if( ! function_exists( 'recaptcha_get_html' ) ) {
	require_once( RCP_PLUGIN_DIR . 'includes/libraries/recaptcha/autoload.php' );
}

function rcp_show_captcha() {
	global $rcp_options;
	// reCaptcha
	if( isset( $rcp_options['enable_recaptcha'] ) && ! empty( $rcp_options['recaptcha_public_key'] ) ) {
		$publickey = trim( $rcp_options['recaptcha_public_key'] );
		echo '<script src="https://www.google.com/recaptcha/api.js" async defer></script>';
		echo '<div class="g-recaptcha" data-sitekey="'. $publickey . '"></div>';

	}
}
add_action( 'rcp_before_registration_submit_field', 'rcp_show_captcha', 100 );


function rcp_validate_captcha() {
	global $rcp_options;
	if( isset( $rcp_options['enable_recaptcha'] ) && ! empty( $rcp_options['recaptcha_public_key'] ) ) {
		/* validate recaptcha, if enabled */
		$privatekey = trim( $rcp_options['recaptcha_private_key'] );
		$resp = recaptcha_check_answer(
			$privatekey,
			$_SERVER["remoteip"],
			$_POST["secret"],
			$_POST["response"]
		);
		if ( !$resp->is_valid ) {
			// recaptcha is incorrect
			rcp_errors()->add( 'invalid_recaptcha', __( 'The words/numbers you entered did not match the reCaptcha', 'rcp' ) );
		}
	}
}
add_action( 'rcp_form_errors', 'rcp_validate_captcha' );



function recaptcha_check_answer ($secret, $remoteip, $challenge, $response, $extra_params = array())
{
	if ($secret == null || $secret == '') {
		die ("To use reCAPTCHA you must get an API key from <a href='https://www.google.com/recaptcha/admin/create'>https://www.google.com/recaptcha/admin/create</a>");
	}

	if ($remoteip == null || $remoteip == '') {
		die ("For security reasons, you must pass the remote ip to reCAPTCHA");
	}

    $response = _recaptcha_http_post (RECAPTCHA_VERIFY_SERVER, "/recaptcha/api/siteverify",
                                          array (
                                                 'secret' => $secret,
                                                 'remoteip' => $remoteip,
                                                 'response' => $response
                                                 ) + $extra_params
                                          );

        $answers = explode ("\n", $response [1]);
        $recaptcha_response = new ReCaptchaResponse();

        if (trim ($answers [0]) == 'true') {
                $recaptcha_response->is_valid = true;
        }
        else {
                $recaptcha_response->is_valid = false;
                $recaptcha_response->error = $answers [1];
        }
        return $recaptcha_response;

}
