<?php

namespace App\Controller;

use App\Entity\JwtToken;
use App\Repository\UserRepository;
use App\Service\JwtService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;

class AuthController extends AbstractController
{
    #[Route('/login', name: 'app_login', methods: ['POST'])]
    public function login(
        Request $request,
        UserRepository $userRepository,
        UserPasswordHasherInterface $passwordEncoder,
        JwtService $jwtService,
        EntityManagerInterface $em
    ): JsonResponse {
        $data = json_decode($request->getContent(), true);
        $email = $data['email'] ?? '';
        $password = $data['password'] ?? '';

        $user = $userRepository->findOneBy(['email' => $email]);

        if (!$user || !$passwordEncoder->isPasswordValid($user, $password)) {
            return new JsonResponse(['error' => 'Invalid credentials.'], JsonResponse::HTTP_UNAUTHORIZED);
        }

        // Generate JWT
        $token = $jwtService->createToken($user);
        $tokenString = $token->toString();
        $expiresAt = $token->claims()->get('exp');

        // Store JWT in the database
        $jwtToken = new JwtToken();
        $jwtToken->setToken($tokenString);
        $jwtToken->setExpiresAt($expiresAt);
        $jwtToken->setUser($user);

        $em->persist($jwtToken);
        $em->flush();

        return new JsonResponse(['token' => $tokenString]);
    }

    #[Route('/logout', name: 'app_logout', methods: ['POST'])]
    public function logout(
        Request $request,
        EntityManagerInterface $em
    ): JsonResponse {
        $authHeader = $request->headers->get('Authorization');

        if (!$authHeader || !str_starts_with($authHeader, 'Bearer ')) {
            return new JsonResponse(['error' => 'Token not provided.'], JsonResponse::HTTP_BAD_REQUEST);
        }

        $tokenString = substr($authHeader, 7);
        $jwtToken = $em->getRepository(JwtToken::class)->findOneBy(['token' => $tokenString]);

        if ($jwtToken) {
            $em->remove($jwtToken);
            $em->flush();
        }

        return new JsonResponse(['message' => 'Successfully logged out.']);
    }
}
