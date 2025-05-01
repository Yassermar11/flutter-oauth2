
import 'package:flutter_oauth2/helpers/constant.dart';
import 'package:flutter_oauth2/services/api_interceptor.dart';
import 'package:http/http.dart';
import 'package:http_interceptor/http/intercepted_client.dart';

class ApiService {
  Client client = InterceptedClient.build(interceptors: [
    ApiInterceptor(),
  ]);

  Future<Response> getSecretArea() async {
    final secretUrl = Uri.parse('${Constants.baseUrl}/secret');
    return await client.get(secretUrl);
  }
}