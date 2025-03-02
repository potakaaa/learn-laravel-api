<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        // $validated = $request->validate([
        //     'name' => 'required|string|max:200',
        //     'email' => 'required|string|email|max:200|unique:users',
        //     'password' => 'required|string|min:8',
        // ]);

        $validated = Validator::make($request->all(), [
            'name' => 'required|string|max:200',
            'email' => 'required|string|email|max:200|unique:users',
            'password' => 'required|string|min:8',
        ]);

        if ($validated->fails()) {
            return response()->json($validated->errors(), 400);
        };

        try {
            $user = User::create([
                'name' => $request->name,
                'email' => $request->email,
                'password' => Hash::make($request->password)
            ]);

            $token = $user->createToken('auth_token')->plainTextToken;

            return response()->json([
                'access_token' => $token,
                'user' => $user
            ], 200);
        } catch (\Exception $e) {
            return response()->json(['error' => $e->getMessage()], 400);
        }
    }
}
