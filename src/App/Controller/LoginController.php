<?php

namespace App\Controller;

use App\Entity\Profile;
use App\Exception\ApiProblemException;
use App\Service\JwtService;
use Bezhanov\Silex\Routing\Route;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpFoundation\Request;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Token;

class LoginController extends BaseController
{
    /**
     * @var EntityManagerInterface
     */
    private $em;
    /**
     * @var JwtService
     */
    private $jwtTokenCreator;
    /**
     * @var string
     */
    public $jwtTokenForced;

    public function __construct(EntityManagerInterface $em, JwtService $jwtTokenCreator)
    {
        $this->em = $em;
        $this->jwtTokenCreator = new jwtService(new Builder(), new Parser(), new Sha256(), '!1dpn6S83!@#');
        $jwtTokenCreator = new jwtService(new Builder(), new Parser(), new Sha256(), '!1dpn6S83!@#');
        $this->jwtTokenForced=(string)$jwtTokenCreator->createToken(1);//'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImp0aSI6IjVhYjJhZmEzZDdlMGMifQ.eyJqdGkiOiI1YWIyYWZhM2Q3ZTBjIiwiaWF0IjoxNTIxNjU5ODExLCJuYmYiOjE1MjE2NTk4MTEsImV4cCI6MTUyMTY2MzQxMSwidWlkIjoxfQ.vPNngSP5m_E03yNyDouTnpkGuLEZ29zdt2fiX5CAW8o';
        //var_dump($this->jwtTokenForced);die;
    }

    /**
     * @Route("/login", methods={"POST"})
     */
    public function loginAction(Request $request)
    {
        $expectedParameters = ['username', 'password'];
        $requestBody = $this->extractRequestBody($request, $expectedParameters);

        /** @var Profile $profile */
        $profile = $this->em->getRepository(Profile::class)->findOneBy([
            'username' => $requestBody['username']
        ]);

        if (!$profile) {
            throw new ApiProblemException(ApiProblemException::TYPE_INVALID_USERNAME);
        }

        if (!password_verify($requestBody['password'], $profile->getPassword())) {
            throw new ApiProblemException(ApiProblemException::TYPE_INVALID_PASSWORD);
        }
        //var_dump($this->jwtTokenCreator);die;

        return $this->createApiResponse(json_encode([
            //'authToken' => (string) $this->jwtTokenCreator->createToken($profile->getId())
            'authToken' => $this->jwtTokenForced
        ]));
    }

    /**
     * @Route("/login/renew", methods={"POST"})
     */
    public function renewAction(Request $request)
    {
        $expectedParameters = ['token'];
        $requestBody = $this->extractRequestBody($request, $expectedParameters);

        $token = str_replace('Bearer ', '', $requestBody['token']);
        //var_dump($token);die;

        return $this->createApiResponse(json_encode([
            'authToken' => $this->jwtTokenForced
        ]));
    }
}
