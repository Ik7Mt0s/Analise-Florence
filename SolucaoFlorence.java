import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import br.edu.icev.aed.forense.Alerta;
import br.edu.icev.aed.forense.AnaliseForenseAvancada;

public class SolucaoFlorence implements AnaliseForenseAvancada {

    private List<Alerta> lerArquivo(String caminhoArquivo) throws IOException {
        List<Alerta> alertas = new ArrayList<>();
        try (BufferedReader br = Files.newBufferedReader(Path.of(caminhoArquivo))) {
            String linha;
            boolean primeira = true;
            while ((linha = br.readLine()) != null) {
                if (primeira) {
                    if (linha.toLowerCase().contains("timestamp")) {
                        primeira = false;
                        continue;
                    }
                    primeira = false;
                }
                String[] cols = linha.split(",");
                if (cols.length < 7) continue;

                long timestamp = Long.parseLong(cols[0].trim());
                String userId = cols[1].trim();
                String sessionId = cols[2].trim();
                String actionType = cols[3].trim();
                String targetResource = cols[4].trim();
                int severityLevel = Integer.parseInt(cols[5].trim());
                long bytesTransferred = Long.parseLong(cols[6].trim());

                alertas.add(new Alerta(timestamp, userId, sessionId, actionType, targetResource, severityLevel, bytesTransferred));
            }
        }
        return alertas;
    }

    @Override
    public Set<String> encontrarSessoesInvalidas(String caminho) throws IOException {
        /*Desafio 1: Encontrar Sessões Inválidas*/

        //Lê o arquivo CSV e transforma cada linha em um objeto "Alerta"
        //Cada Alerta representa um evento do log (LOGIN, LOGOUT etc.)
        List<Alerta> alertas = lerArquivo(caminho);

        //Cria um conjunto (Set) para armazenar as sessões inválidas.
        //HashSet é usado porque não permite duplicatas e tem busca rápida (O(1)).
        Set<String> invalidas = new HashSet<>(1 << 16);

        //Cria um mapa que relaciona cada usuário (userId) a uma pilha (Deque) de sessões.
        //Essa pilha vai representar as sessões abertas por usuário.
        Map<String, Deque<String>> pilhasPorUsuario = new HashMap<>(1 << 16);
        
        //Flag usada para detectar se o arquivo está fora de ordem cronológica.
        boolean foraDeOrdem = false;

        //Faz uma varredura rápida para verificar se há algum timestamp fora de ordem.
        //Se o timestamp atual for menor que o anterior, o log está "embaralhado".
        for (int i = 1; i < alertas.size(); i++){
            if (alertas.get(i).getTimestamp() < alertas.get(i-1).getTimestamp()){
                foraDeOrdem = true;
                break; //Basta detectar um caso fora de ordem para decidir ordenar.
            }
        }

        //Se o arquivo estiver fora de ordem, ordena todos os eventos pelo timestamp.
        //Isso garante que os LOGIN e LOGOUT sejam processados na sequência temporal correta.
        if (foraDeOrdem){
            alertas.sort(Comparator.comparingLong(Alerta::getTimestamp));
        }

        //Agora percorre cada evento do log (um por linha)
        for (Alerta a: alertas){

            //Extrai os campos essenciais do evento
            String user = a.getUserId();
            String session = a.getSessionId();
            String action = a.getActionType();
            
            //Se algum campo obrigatório estiver faltando, pula a linha (evita NullPointerException)
            if (user == null || session == null || action == null) {
                continue;
            }

            //Remove espaços em branco antes/depois (segurança extra contra logs sujos)
            user = user.trim();
            session = session.trim();
            action = action.trim();

            //Se ainda assim o campo estiver vazio, ignora o evento.
            if (user.isEmpty() || session.isEmpty() || action.isEmpty()){
                continue;
            }

            //Pega a pilha de sessões do usuário atual.
            //Se ele ainda não tiver uma, cria uma nova e adiciona ao mapa.
            Deque<String> pilha = pilhasPorUsuario.get(user);
            if (pilha == null) {
                pilha = new ArrayDeque<>();
                pilhasPorUsuario.put(user, pilha);
            }

            // === Lógica das sessões inválidas ===

            //Caso o evento seja um LOGIN:
            if (action.equalsIgnoreCase("LOGIN")){
                //Se a pilha não estiver vazia, quer dizer que o usuário ainda não fez LOGOUT
                //da sessão anterior — então esta nova sessão é inválida.
                if (!pilha.isEmpty()){
                    invalidas.add(session);
                }

                //Empilha (registra) a nova sessão como ativa.
                pilha.push(session);
            }

            //Caso o evento seja um LOGOUT:
            else if (action.equalsIgnoreCase("LOGOUT")){
                
                // Se a pilha estiver vazia, é um LOGOUT sem LOGIN — sessão inválida.
                if (pilha.isEmpty()){
                    invalidas.add(session);
                }

                // Se o topo da pilha (última sessão aberta) for diferente da atual,
                // quer dizer que o usuário está tentando fechar a sessão errada (fora de ordem).
                else if (!pilha.peek().equals(session)) {
                    invalidas.add(session);
                }

                // Caso contrário, está tudo certo: o LOGOUT corresponde ao último LOGIN.
                // Então removemos a sessão da pilha (sessão encerrada com sucesso).
                else {
                    pilha.pop();
                }
            }
        }

        //Depois de processar todos os eventos, ainda pode haver sessões que nunca foram fechadas.
        //Cada sessão que sobrar na pilha é considerada inválida (sem LOGOUT correspondente).
        for (Deque<String> pilha : pilhasPorUsuario.values()){
            while (!pilha.isEmpty()) invalidas.add(pilha.pop());
        }

        //Retorna o conjunto final com todas as SESSION_IDs inválidas.
        //(O Set evita duplicatas automaticamente.)
        return invalidas;
    }

    @Override
    public List<String> reconstruirLinhaTempo(String arg0, String arg1) throws IOException {
        /*Desafio 2: Reconstruir Linha do Tempo*/
        throw new UnsupportedOperationException("Unimplemented method 'reconstruirLinhaTempo'");
    }
    
    @Override
    public List<Alerta> priorizarAlertas(String arg0, int arg1) throws IOException {
        /*Desafio 3: Priorizar Alertas*/
        throw new UnsupportedOperationException("Unimplemented method 'priorizarAlertas'");
    }
    
    @Override
    public Map<Long, Long> encontrarPicosTransferencia(String arg0) throws IOException {
        /*Desafio 4: Encontrar Picos de Transferência*/
        throw new UnsupportedOperationException("Unimplemented method 'encontrarPicosTransferencia'");
    }

    @Override
    public Optional<List<String>> rastrearContaminacao(String arg0, String arg1, String arg2) throws IOException {
        /*Desafio 5: Rastrear Contaminação*/
        throw new UnsupportedOperationException("Unimplemented method 'rastrearContaminacao'");
    }
    
}
