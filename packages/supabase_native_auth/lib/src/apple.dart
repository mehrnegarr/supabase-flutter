import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:flutter/foundation.dart';
import 'package:sign_in_with_apple/sign_in_with_apple.dart';
import 'package:supabase_flutter/supabase_flutter.dart';
import 'package:supabase_native_auth/src/common.dart';

extension Apple on GoTrueClient {
  /// Signs a user in using native Apple Login.
  ///
  /// This method only works on iOS and MacOS. If you want to sign in a user using Apple
  /// on other platforms, please use the `signInWithOAuth` method.
  ///
  /// This method is experimental as the underlying `signInWithIdToken` method is experimental.
  Future<AuthResponse> signInWithApple() async {
    assert(!kIsWeb && (Platform.isIOS || Platform.isMacOS),
        'Please use signInWithOAuth for non-iOS platforms');
    final rawNonce = generateRandomString();
    final hashedNonce = sha256.convert(utf8.encode(rawNonce)).toString();

    final credential = await SignInWithApple.getAppleIDCredential(
      scopes: [
        AppleIDAuthorizationScopes.email,
        AppleIDAuthorizationScopes.fullName,
      ],
      nonce: hashedNonce,
    );

    final idToken = credential.identityToken;
    if (idToken == null) {
      throw const AuthException(
          'Could not find ID Token from generated credential.');
    }

    return signInWithIdToken(
      provider: Provider.apple,
      idToken: idToken,
      nonce: rawNonce,
    );
  }
}
