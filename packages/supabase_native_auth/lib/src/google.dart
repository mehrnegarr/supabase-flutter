import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter_appauth/flutter_appauth.dart';
import 'package:supabase_flutter/supabase_flutter.dart';
import 'package:supabase_native_auth/src/common.dart';

extension Google on GoTrueClient {
  /// Signs a user in using native Google Login.
  ///
  ///
  /// [iosClientId] is the client ID for iOS registered on Google Cloud Platform
  ///
  /// [androidClientId] is the client ID for Android registered
  /// on Google Cloud Platform
  ///
  /// This method only works on iOS and Android. Use `signInWithOAuth`
  /// on other platforms.
  Future<AuthResponse> signInWithGoogle({
    required String packageName,
    String? iosClientId,
    String? androidClientId,
  }) async {
    assert(
      !kIsWeb && (Platform.isIOS || Platform.isAndroid),
      'Please use signInWithOAuth for platform other than iOS or Android',
    );
    assert(
      (Platform.isIOS && iosClientId != null) ||
          (Platform.isAndroid && androidClientId != null),
      'Please set the respective client ID for the platform',
    );

    final rawNonce = generateRandomString();
    final hashedNonce = sha256.convert(utf8.encode(rawNonce)).toString();

    final clientId = Platform.isIOS ? iosClientId! : androidClientId!;

    /// fixed for google login
    final redirectUrl = '$packageName:/google_auth';

    /// fixed for google login
    const discoveryUrl =
        'https://accounts.google.com/.well-known/openid-configuration';

    const appAuth = FlutterAppAuth();

    // authorize the user by opening the concent page
    final result = await appAuth.authorize(
      AuthorizationRequest(
        clientId,
        redirectUrl,
        discoveryUrl: discoveryUrl,
        nonce: hashedNonce,
        scopes: [
          'openid',
          'email',
        ],
      ),
    );

    if (result == null) {
      throw const AuthException(
          'Could not find AuthorizationResponse after authorizing');
    }

    // Request the access and id token to google
    final tokenResponse = await appAuth.token(
      TokenRequest(
        clientId,
        redirectUrl,
        authorizationCode: result.authorizationCode,
        discoveryUrl: discoveryUrl,
        codeVerifier: result.codeVerifier,
        nonce: result.nonce,
        scopes: [
          'openid',
          'email',
        ],
      ),
    );

    final idToken = tokenResponse?.idToken;

    if (idToken == null) {
      throw const AuthException(
          'Could not find idToken from the token response');
    }

    return signInWithIdToken(
      provider: Provider.google,
      idToken: idToken,
      accessToken: tokenResponse?.accessToken,
      nonce: rawNonce,
    );
  }
}
