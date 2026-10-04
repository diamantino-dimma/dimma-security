'use strict';

/**
 * Bloqueia qualquer requisicao HTTP que tente acessar diretamente um
 * arquivo .dimma (ex: GET /security.dimma pelo navegador). O arquivo
 * .dimma pode conter informacoes sensiveis sobre a postura de seguranca
 * do projeto e NUNCA deve ser servido como conteudo estatico — o mesmo
 * cuidado que se toma com um arquivo .env.
 *
 * IMPORTANTE: isto e uma camada de defesa em profundidade DENTRO da
 * aplicacao. A defesa primaria e configurar o servidor web (Nginx,
 * Apache, etc.) para negar acesso a *.dimma antes mesmo da requisicao
 * chegar no codigo da aplicacao — veja a documentacao (DIMMA_SYNTAX.md).
 *
 * Este middleware deve ser registrado ANTES de qualquer
 * express.static(...) no app, senao o Express pode servir o arquivo
 * antes de chegar aqui.
 */
function blockDirectAccessMiddleware() {
  return function dimmaBlockDirectAccess(req, res, next) {
    let requestPath = req.path || '';
    for (let i = 0; i < 8; i++) {
      if (requestPath.toLowerCase().endsWith('.dimma')) {
        return res.status(404).send('Not Found');
      }

      let decodedPath;
      try {
        decodedPath = decodeURIComponent(requestPath);
      } catch (err) {
        if (err instanceof URIError) {
          return res.status(400).send('Bad Request');
        }
        return next(err);
      }

      if (decodedPath === requestPath) {
        return next();
      }
      requestPath = decodedPath;
    }

    return res.status(400).send('Bad Request');
  };
}

module.exports = { blockDirectAccessMiddleware };
