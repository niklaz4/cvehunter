<h1>CVEHunter</h1>

<p><strong>CVEHunter</strong> é uma ferramenta de linha de comando desenvolvida para facilitar a pesquisa e a análise das técnicas do MITRE ATT&CK, desenvolvida especialmente para sistemas operacionais Linux. Este projeto foi criado para ajudar profissionais de segurança a identificar e entender as táticas e técnicas utilizadas por ameaças cibernéticas, permitindo que os usuários realizem buscas por técnicas específicas e exportem os dados para diferentes formatos.</p>

<h2>Objetivo</h2>
<p>O principal objetivo do CVEHunter é fornecer uma interface intuitiva para a exploração da base de dados do MITRE ATT&CK, permitindo que os usuários:</p>
<ul>
    <li>Busquem técnicas com base em palavras-chave.</li>
    <li>Filtragem por táticas e níveis de severidade.</li>
    <li>Exportem os resultados para arquivos CSV ou JSON.</li>
    <li>Visualizem as técnicas em um formato de tabela clara e organizada.</li>
</ul>

<h2>Motivação</h2>
<p>A crescente complexidade das ameaças cibernéticas e a necessidade de uma resposta rápida e eficiente exigem que os profissionais de segurança estejam sempre atualizados. O CVEHunter foi criado para facilitar o acesso às informações do MITRE ATT&CK, permitindo uma análise mais rápida e fundamentada das técnicas utilizadas pelos atacantes.</p>

<h2>Como Rodar o Código</h2>
<p>Para executar o CVEHunter, siga os passos abaixo:</p>
<ol>
    <li><strong>Clone o repositório:</strong></li>
    <pre><code>git clone https://github.com/niklaz4/cvehunter.git</code></pre>

    <li><strong>Instale as dependências:</strong></li>
    <pre><code>pip install -r requirements.txt</code></pre>

    <li><strong>Execute o programa:</strong></li>
    <pre><code>python main.py [opções]</code></pre>
    <p>Alguns dos exemplos disponíveis são:</p>
    <ul>
        <li><strong>Busca básica:</strong></li>
        <pre><code>python main.py -k "password"</code></pre>

        <li><strong>Busca por tática específica (ex: Initial Access):</strong></li>
        <pre><code>python main.py -t "TA0001"</code></pre>

        <li><strong>Busca combinada:</strong></li>
        <pre><code>python main.py -k "credentials" -t "TA0006" -s "ALTO"</code></pre>

        <li><strong>Exportar resultados:</strong></li>
        <pre><code>python main.py -k "lateral" -e csv -f "techniques.csv"</code></pre>
    </ul>

    <li><strong>Outro exemplo de uso:</strong></li>
    <pre><code>python main.py -k "Phishing" -t "TA0001" -s "ALTO" -e "csv" -f "resultados.csv"</code></pre>
</ol>

<h2>Contribuições</h2>
<p>Contribuições são bem-vindas! Sinta-se à vontade para abrir issues ou pull requests. É um projeto open-source.</p>

