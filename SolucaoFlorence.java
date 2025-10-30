import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import br.edu.icev.aed.forense.Alerta;
import br.edu.icev.aed.forense.AnaliseForenseAvancada;

public class SolucaoFlorence implements AnaliseForenseAvancada {

    public List<Alerta> lerArquivo(String caminhoArquivo) throws IOException {
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
    public Set<String> encontrarSessoesInvalidas(String arg0) throws IOException {
        /*Desafio 1: Encontrar Sessões Inválidas*/
        throw new UnsupportedOperationException("Unimplemented method 'encontrarSessoesInvalidas'");
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
