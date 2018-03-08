import * as encrypt from 'crypto';
import * as cookies from 'cookie-parser';
import * as parsing from 'body-parser';
import * as jwtoken from 'jsonwebtoken';
import * as express from 'express';

/**
 * axsrfWithCors implementation.
 * 
 * ...
 * 
 * @author Kirk Bulis
 */
function axsrfWithCors(options: {
  hashingSecretKey: string,
  hashingAlgorithm: string,
  allowOrigin?: string,
  jsonLimit?: number,
  identify: (res: express.Response, member?: any) => void,
}): express.RequestHandler[] {
  return [
    parsing.json({
      limit: options.jsonLimit || 64 * 1024,
    }),
    cookies('', {
      decode: (value) => {
        return value;
      }
    }),
    (req: express.Request, res: express.Response, next: express.NextFunction) => {
      res.header('Access-Control-Allow-Headers', req.header('Access-Control-Request-Headers'));
      res.header('Access-Control-Allow-Origin', options.allowOrigin ? options.allowOrigin === '*' ? req.header('Origin') : options.allowOrigin : '*');
      res.header('Access-Control-Allow-Credentials', 'true');
      res.header('Vary', 'Origin');

      next();
    },
    (req: express.Request, res: express.Response, next: express.NextFunction) => {
      try {
        let encoded = req.headers['authorization'] as string || '';

        if (encoded.length > 6 && encoded.substr(0, 6).toLowerCase() === 'bearer') {
          encoded = encoded.substr(7).trim();
        }

        if (encoded.length === 0) {
          encoded = req.query['token'] as string || '';
        }

        if (encoded === 'null') {
          encoded = '';
        }

        if (encoded.length !== 0) {
          try {
            let extracted: { axsrf: string, iat: number, exp: number } = {
              ...(jwtoken.verify(encoded, options.hashingSecretKey) as any),
            };

            if (extracted.exp && extracted.exp > (+new Date / 1000)) {
              if (req.cookies['axsrf'] && extracted.axsrf === encrypt.createHmac(options.hashingAlgorithm, options.hashingSecretKey).update(req.cookies['axsrf']).digest('base64')) {
                options.identify(res, extracted);

                next();

                return;
              }
            }
          }
          catch (eX) {
            console.log(eX);
          }
        }
      }
      catch (eX) {
      }

      options.identify(res);

      next();
    },
    (req: express.Request, res: express.Response, next: express.NextFunction) => {
      if (!res.locals.generateTokenWithAxsrf) {
        res.locals.generateTokenWithAxsrf = (payload: any, expiresIn: string, onlySecure: boolean) => {
          const axsrf = 'a' + (Math.floor(Math.random() * 900000000000000) + 100000000000000);

          res.cookie('axsrf', axsrf, {
            httpOnly: true,
            secure: onlySecure,
          });

          return jwtoken.sign({
            axsrf: encrypt.createHmac(options.hashingAlgorithm, options.hashingSecretKey).update(axsrf).digest('base64'),
            ...payload
          }, options.hashingSecretKey, {
              expiresIn: expiresIn,
          }) as string;
        };
      }

      next();
    },
  ];
}

export {
  axsrfWithCors,
};
