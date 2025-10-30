import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import br.edu.icev.aed.forense.Alerta;
import br.edu.icev.aed.forense.AnaliseForenseAvancada;

public class SolucaoFlorence implements AnaliseForenseAvancada {

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
