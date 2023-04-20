<?php

namespace nguyenanhung\Backend\BaseAPI\Http;

use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\Facebook;
use League\OAuth2\Client\Provider\Google;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;



/**
 * Class WebServiceAccount
 *
 * @package   nguyenanhung\Backend\BaseAPI\Http
 * @author    713uk13m <dev@nguyenanhung.com>
 * @copyright 713uk13m <dev@nguyenanhung.com>
 */
class WebServiceSSOLogin extends BaseHttp
{
    protected const API_NAME = 'social login';
    protected const LIST_STATE = ['google', 'facebook', 'instagram', 'linkedin', 'github'];
    protected const MES = array(
        'stateNotFound' => "phuong thuc login khong ton tai, hay thu lai",
    );
    private $state;
    private $session;
    private $request;

    /**
     * WebServiceSSOLogin constructor.
     *
     * @param array $options
     *
     * @author   : 713uk13m <dev@nguyenanhung.com>
     * @copyright: 713uk13m <dev@nguyenanhung.com>
     */
    public function __construct(array $options = array())
    {
        parent::__construct($options);
        $this->session = new Session();
        $this->request = Request::createFromGlobals();
        $this->logger->setLoggerSubPath(__CLASS__);
    }

    public function setState($state): self
    {
        $this->state = $state;
        $this->logger->debug(__METHOD__, 'Login by: ' . $state);

        return $this;
    }

    public function login(): self
    {
        if (!in_array($this->state, self::LIST_STATE, true)) {
            $response = array(
                'status_code' => Response::HTTP_NOT_FOUND,
                'desc'        => self::MES['stateNotFound'],
                'login by'    => $this->state
            );
            $this->logger->error(__METHOD__, $response['desc'] . ' list state support:', self::LIST_STATE);

            $this->response = $response;

            return $this;
        }

        $this->logger->info(self::API_NAME . '.' . __FUNCTION__, 'SSO Login with ' . strtoupper($this->state));

        if ($this->state === 'google') {
            return $this->googleLogin();
        }

        if ($this->state === 'facebook') {
            return $this->facebookLogin();
        }

        return $this;
    }

    protected function facebookLogin(): WebServiceSSOLogin
    {
        $this->response = $this->oauth2Service(new Facebook($this->options[$this->state]), $this->request);

        return $this;
    }

    protected function googleLogin(): WebServiceSSOLogin
    {
        $this->response = $this->oauth2Service(new Google($this->options[$this->state]), $this->request);

        return $this;
    }

    protected function oauth2Service($provider, $request): array
    {
        if (!empty($request->query->get('error'))) {
            $response = array(
                'status_code' => Response::HTTP_INTERNAL_SERVER_ERROR,
                'desc'        => 'Got error: ' . htmlspecialchars($request->query->get('error'), ENT_QUOTES),
            );
        } elseif (empty($request->query->get('code'))) {
            // If we don't have an authorization code then get one
            $authUrl = $provider->getAuthorizationUrl();
            $this->session->set('oauth2state', $provider->getState());

            $response = array(
                'status_code' => Response::HTTP_OK,
                'desc'        => self::API_NAME . '-' . 'sucess',
                'data'        => $authUrl
            );
        } else {
            try {
                // Try to get an access token (using the authorization code grant)
                $token = $provider->getAccessToken('authorization_code', [
                    'code' => $request->query->get('code')
                ]);

                // Optional: Now you have a token you can look up a users profile data
                // We got an access token, let's now get the owner details
                $ownerDetails = $provider->getResourceOwner($token);
                $this->session->set('userLogin', serialize($ownerDetails));
                $response = array(
                    'status_code' => Response::HTTP_OK,
                    'desc'        => self::API_NAME . '-' . 'Success',
                    'data'        => serialize($ownerDetails),
                );
            } catch (IdentityProviderException $e) {
                $this->logger->error(__CLASS__ . '.' . __FUNCTION__,
                    'File: ' . $e->getFile() . '-Line:' . $e->getLine() . '-Message:' . $e->getMessage());
                $response = array('desc' => 'Something went wrong: ' . $e->getMessage());
            }
        }

        return $response;
    }
}