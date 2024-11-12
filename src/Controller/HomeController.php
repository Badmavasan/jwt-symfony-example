<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\File\Exception\AccessDeniedException;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Routing\Attribute\Route;

class HomeController extends AbstractController
{
    #[Route('/homepage', name: 'app_homepage', methods: ['GET'])]
    public function index(): JsonResponse
    {
        // Check if the user is authenticated
        $user = $this->getUser();

        if (!$user) {
            // If the user is not authenticated, throw an exception or return an error response
            return new JsonResponse(['error' => 'You are not authenticated.'], JsonResponse::HTTP_UNAUTHORIZED);
        }

        // If the user is authenticated, return a welcome message
        return new JsonResponse([
            'message' => 'Welcome to the homepage!',
            'user' => [
                'id' => $user->getId(),
                'email' => $user->getEmail(),
            ],
        ]);
    }
}
