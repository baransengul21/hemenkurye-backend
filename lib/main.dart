import 'package:flutter/material.dart';
import 'screens/login_screen.dart';

void main() {
  runApp(const HemenKuryeApp());
}

class HemenKuryeApp extends StatelessWidget {
  const HemenKuryeApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'HemenKurye',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        primarySwatch: Colors.orange,
        useMaterial3: true,
      ),
      home: const LoginScreen(),
    );
  }
}