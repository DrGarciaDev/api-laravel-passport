<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

use Validator;
use Hash;
use Auth;

use App\Models\User;

class AuthController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['register', 'login']]);
    }

    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name'     => 'required|string|max:255',
            'email'    => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:6|confirmed',
        ]);

        if($validator->fails()){
            return response()->json([
                'success' => false,
                'message' => 'Falló la validación',
                'error'   => $validator->errors()
            ], 422);
        }

        $user = User::create([
            'name'     => $request->get('name'),
            'email'    => $request->get('email'),
            'password' => Hash::make($request->get('password')),
        ]);

        $access_token = $user->createToken('authTesToken')->accessToken;

        return response([
            'success'      => true,
            'user'         => $user,
            'access_token' => $access_token
        ], 200);
    }

    public function login(Request $request)
    {
        $credentials = $request->only('email', 'password');

        if ( ! Auth::attempt($credentials) ) {
            return response([
                'success' => false,
                'message' => 'Usuario o contraseña inválido'
            ], 401);
        }

        $access_token = Auth::user()->createToken('authTesToken')->accessToken;

        return response([
            'success'      => true,
            'user'         => Auth::user(),
            'access_token' => $access_token
        ], 200);
    }

    public function users(Request $request)
    {
        $users = User::all();

        return response([
            'success'      => true,
            'user'         => $users,
        ], 200);
    }
}
