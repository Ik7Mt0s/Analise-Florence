package scc;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.PriorityQueue;
import java.util.Queue;
import java.util.Set;
import java.util.*;

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
    public List<String> reconstruirLinhaTempo(String caminho, String sessionId) throws IOException {
        /*Desafio 2: Reconstruir Linha do Tempo*/
        //Lê o arquivo CSV e transforma cada linha em um objeto "Alerta"
        //O metodo já foi implementado antes
        List<Alerta> alertas = lerArquivo(caminho);
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
        //Isso garante que os eventos sejam processados na sequência temporal correta.
        if (foraDeOrdem){
            alertas.sort(Comparator.comparingLong(Alerta::getTimestamp));
        }
        //Cria uma fila que irá armazenar os actionTypes temporariamente de forma que a ordem cronológica seja mantida
        Queue<String> fila = new LinkedList<>();
        //Percorre todos os alertas do arquivo
        for(Alerta i: alertas){
            //Verifica se o alerta pertence ao sessionId
            //Os alertas com o mesmo sessionId serão usados para reconstruir a linha do tempo
            if(i.getSessionId().equals(sessionId)){
                //Adiciona o actionType na fila
                fila.add(i.getActionType());
            }
        }
        //Retorna uma lista contendo todos os actionTypes da sessão, em ordem cronológica
        //Converte a Fila em ArrayList para respeitar o tipo de retorno
        List<String> resultado = new ArrayList<>();
        //Enquanto a fila não estiver vazia, remove o primeiro elemento e adiciona à lista de resultado
        while(!fila.isEmpty()){
            resultado.add(fila.poll());
        }
        //Quando a Fila estiver vazia, retorna a lista resultado
        return resultado;
    }

    @Override
    public List<Alerta> priorizarAlertas(String caminho, int n) throws IOException {
        /*Desafio 3: Priorizar Alertas*/

        //Casos inválidos: se n <= 0, não tem "top-N" pra retornar, retornando uma lista vazia
        if (n <= 0) {
            return Collections.emptyList();
        }

        //Lê todo o arquivo e converte em List<Alerta>
        List<Alerta> alertas = lerArquivo(caminho);

        //Arquivo sem dados: retorna lista vazia
        if (alertas.isEmpty()) {
            return Collections.emptyList();
        }
        
        //COMPARATOR DO HEAP (PRIORIDADE ASC = "pior primeiro"):
        //menor severity é pior
        //em empate: timestamp menor (mais antigo) é pior
        //depois: userId asc, sessionId asc (determinismo; nulls não quebram)
        Comparator<Alerta> comparador = Comparator.comparingInt(Alerta::getSeverityLevel).thenComparingLong(Alerta::getTimestamp).thenComparing(Alerta::getUserId, Comparator.nullsFirst(String::compareTo)).thenComparing(Alerta::getSessionId, Comparator.nullsFirst(String::compareTo));

        //Fila de prioridade com capacidade inicial n e "pior primeiro" no topo
        Queue<Alerta> filaPrioridade = new PriorityQueue<>(n, comparador);
        
        //Varre todos os alertas e mantém só os N melhores no heap
        for (Alerta a: alertas){
            if (filaPrioridade.size() < n) {
                //ainda não encheu: apenas adiciona
                filaPrioridade.offer(a);
            }
            else{
                // fila cheia: compara com o "pior" atual (peek)
                // se 'a' for melhor que o pior da fila, troca
                if (comparador.compare(a, filaPrioridade.peek()) > 0) {
                    filaPrioridade.poll(); //remove o pior
                    filaPrioridade.offer(a); //insere novo "melhor"
                }
            }
        }

        //Copia o top n da fila para uma lista
        List<Alerta> resultado = new ArrayList<>(filaPrioridade);

        //COMPARATOR DE SAÍDA (EXIBIÇÃO): agora é prioridade DESC
        //maior severity primeiro
        //desempate: timestamp maior (mais recente) primeiro
        //depois: userId asc e sessionId asc (ordem determinística)
        Comparator<Alerta> outComparador = Comparator.comparingInt(Alerta::getSeverityLevel).reversed().thenComparingLong(Alerta::getTimestamp).reversed().thenComparing(Alerta::getUserId, Comparator.nullsFirst(String::compareTo)).thenComparing(Alerta::getSessionId, Comparator.nullsFirst(String::compareTo));

        //Ordena a lista final no sentido correto para retornar
        resultado.sort(outComparador);

        return resultado;
    }

    @Override
    public Map<Long, Long> encontrarPicosTransferencia(String arg0) throws IOException {
        /*Desafio 4: Encontrar Picos de Transferência*/
        throw new UnsupportedOperationException("Unimplemented method 'encontrarPicosTransferencia'");
    }

    @Override
    public Optional<List<String>> rastrearContaminacao(String caminho, String recursoInicial, String recursoAlvo) throws IOException {
        /*Desafio 5: Rastrear Contaminação*/
        
        // Se qualquer parâmetro for nulo → não dá para rastrear nada.
        if (recursoInicial == null || recursoAlvo == null) {
            return Optional.empty();
        }

        // Remove espaços e normaliza o texto.
        String inicio = recursoInicial.trim();
        String alvo = recursoAlvo.trim();

        // Segurança extra: se ainda assim for nulo (não acontece na prática), retorna vazio.
        if (inicio == null || alvo == null) {
            return Optional.empty();
        }

        // Caso trivial: o início é igual ao alvo → caminho de tamanho 1.
        if (inicio.equals(alvo)) {
            return Optional.of(java.util.Collections.singletonList(inicio));
        }

        // Lê o CSV e produz uma lista de objetos Alerta
        List<Alerta> alertas = lerArquivo(caminho);
        if (alertas.isEmpty()){
            return Optional.empty();
        }

        // Arquivo vazio → nenhum grafo possível
        if (alertas.isEmpty()) {
            return Optional.empty();
        }

        // Mapa: SESSION_ID -> lista de alertas dessa sessão
        Map<String, List<Alerta>> porSessao = new HashMap<>();

        for(Alerta a: alertas){
            String sessao = a.getSessionId();
            if (sessao == null){
                // Evento sem SESSION_ID não entra na análise de contaminação
                continue;
            }

            // Cria a lista da sessão se não existir e adiciona o alerta nela
            porSessao.computeIfAbsent(sessao, k -> new ArrayList<>()).add(a);
        }

        // Adjacência: recurso_origem -> lista de recursos_destino
        Map<String, List<String>> adj = new HashMap<>();

        // Para cada sessão, vamos construir transições entre recursos
        for (List<Alerta> eventos : porSessao.values()){

            // Se tiver menos de 2 alertas, não há transição.
            if (eventos.size()<2) {                
                continue;
            }

            // Ordena eventos da sessão pela ordem do tempo (timestamp cres.)
            eventos.sort(Comparator.comparingLong(Alerta::getTimestamp));

            String anterior = null;

            // Percorre os recursos da sessão
            for(Alerta a : eventos){

                // Ignora recursos nulos ou vazios
                String atual = a.getTargetResource();
                if (atual == null) {
                    continue;
                }
                atual = atual.trim();
                if (atual.isEmpty()) {
                    continue;
                }

                // Se existe recurso anterior e mudou de recurso,
                // cria um aresta no grafo: anterior -> atual
                if (anterior != null && !anterior.equals(atual)) {
                    adj.computeIfAbsent(anterior, k -> new ArrayList<>()).add(atual);
                }

                // Atual vira o anterior para o próximo loop
                anterior = atual;
            }
        }

        // Se o grafo está vazio (nenhuma transição), não existe caminho
        if (adj.isEmpty()) {
            return Optional.empty();
        }


        // ===== BFS =====
        Deque<String> fila = new ArrayDeque<>(); // fila do BFS
        Map<String, String> pai = new HashMap<>(); // para reconstruir caminho
        Set<String> visitado = new HashSet<>(); // evita revisitar nós
        
        fila.add(inicio);
        visitado.add(inicio);
        pai.put(inicio, null);

        while (!fila.isEmpty()) {
            String u = fila.poll(); // remove da fila

            // Pega vizinhos (recursos acessados logo depois)
            List<String> vizinhos = adj.get(u);
            if (vizinhos == null) continue;

            for(String v: vizinhos){
                // Se ainda não visitado, entra na BFS
                if (!visitado.contains(v)) {
                    visitado.add(v);
                    pai.put(v, u);
                    fila.add(v);

                    // Se achamos o alvo → encerramos a busca (early exit)
                    if (v.equals(alvo)) {
                        fila.clear();
                        break;
                    }
                }
            }
        }

        // BFS terminou e o alvo não foi encontrado
        if (!pai.containsKey(alvo)) {
            return Optional.empty();
        }

        // ===== Reconstrução do caminho =====
        List<String> caminhoList = new ArrayList<>();

        // Volta dos pais até chegar no início
        for (String atual = alvo; atual != null; atual = pai.get(atual)) {
            caminhoList.add(atual);
        }
        Collections.reverse(caminhoList);

        // O caminho foi reconstruído ao contrário -> inverte
        return Optional.of(caminhoList);
    }
    
}
