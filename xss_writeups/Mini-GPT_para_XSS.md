# Mini-GPT para XSS

> **Author**: Michelle Mesquita
> **Published**: Jan 27, 2026

---

![Michelle Mesquita](https://miro.medium.com/v2/resize:fill:32:32/1*7g96EP-vba2PxzKT9rEB6g.jpeg)

Share

![image](https://miro.medium.com/v2/resize:fit:700/1*V_0Q1FRKtD-6D2WX8gZ6eQ.png)

Olá, pessoal. Tudo bem?

Nesses últimos meses, estava vendo o vídeo abaixo no YouTube sobre como criar um mini GPT, utilizando GPT-2 e mostrando como que é possível prever as próximas palavras. Isso me deixou ainda mais intrigada a tentar algo (mais simples), e entender o processo de como criar uma IA Generativa, no qual tem objetivo criar um contexto à partir dos diversos dados que possui, prevendo as próximas palavras, utilizando muita das vezes a lei da similaridade (um grande exemplo disso, é pela lei dos cossenos!)

Vou explicar alguns pontos à baixo, mas deixando claro que o objetivo é entender um pouco de como funciona esse processo. Como também, o dataset que utilizei é bastante simples. Assim, não me permitia ter um grande contexto

## Cross site scripting XSS dataset for Deep learning

### Kaggle is the world's largest data science community with powerful tools and resources to help you achieve your data…

www.kaggle.com

Vamos la :)

O projeto combina aprendizado profundo com transformers, fine-tuning usando LoRA, e integração com ferramentas modernas como Ollama

## Detecção de XSS

Cross-Site Scripting (XSS) é uma das vulnerabilidades mais comuns em aplicações web. Ela ocorre quando código JavaScript malicioso é injetado em páginas web, permitindo que atacantes executem scripts no contexto de outros usuários. Detectar essas vulnerabilidades manualmente em grandes bases de código é trabalhoso e propenso a erros

## O que são embeddings?

Embeddings são representações numéricas (vetores) de texto ou código. Cada trecho de código é convertido em um vetor de 256 dimensões que captura características semânticas

Esses vetores permitem que o modelo “entenda” similaridades entre diferentes trechos de código.

![image](https://miro.medium.com/v2/resize:fit:700/1*77XRMbAfMgxHWz4ymHC6kA.png)

![image](https://miro.medium.com/v2/resize:fit:700/1*ttXwU0wbOmHGwZXG5iQwrg.png)

## Lei do Cosseno e Similaridade

É usada para medir similaridade entre dois vetores. A fórmula é:

similaridade = cos(θ) = (A · B) / (||A|| × ||B||)

Onde:

- O resultado varia de -1 (opostos) a 1 (idênticos)

No nosso código:

```
def cosine_sim(model, text1, text2):
  emb1 = model.get_embedding(text1) # Embedding do texto 1
  emb2 = model.get_embedding(text2) # Embedding do texto 2
  return F.cosine_similarity(emb1.unsqueeze(0), emb2.unsqueeze(0)).item()
```

Se dois trechos de código têm embeddings similares (cosseno próximo de 1), provavelmente terão características semelhantes em termos de segurança.

![image](https://miro.medium.com/v2/resize:fit:700/1*9NUDSAymhcM1Pyb3s5h74A.png)

## Transformers: O Coração do Modelo

Transformers são arquiteturas de deep learning baseadas em atenção (attention). Eles processam sequências de tokens (caracteres, no nosso caso) e aprendem relações entre eles.

![image](https://miro.medium.com/v2/resize:fit:700/1*-N1h_6yYXqM8Zf5FHVuLzg.png)

## Como funciona o “Mini GPT”

1- Tokenização Char-level

Usa vocabulário pequeno, capturando padrões em diferentes linguagens

```
def encode(s): 
    return [stoi[c] for c in s if c in stoi]  # "echo" → [5, 3, 8, 12]

def decode(ids): 
    return "".join([itos[i] for i in ids])  # [5, 3, 8, 12] → "echo"
```

2- Embedding de tokens

Cada caracter tem um significado

```
tok_emb = self.token_emb(x)  # (B, T, d_model) - "significado" do caractere
pos_emb = self.pos_emb[:, :T, :]  # (1, T, d_model) - posição na sequência
x = tok_emb + pos_emb  # Combina significado + posição
```

3- Self-Attention

Cada posição “olha” apenas para posições anteriores (não vê o futuro), essencial para geração autoregressiva

```
mask = torch.triu(torch.ones(T, T), diagonal=1).bool()  # Máscara causal
x = self.transformer(x, mask=mask)
```

4- Feed-Forward Network

Permite aprendizado de padrões não-lineares complexos. A expansão 4× é padrão de transformers

```
# Expande temporariamente: 256 → 1024 → 256
dim_feedforward = 4 * d_model  # 1024
```

## Dimensões (B, T, d_model) e (1, T, d_model)

- B (Batch): Número de exemplos processados simultaneamente (batch_size = 32)

- T (Time/Sequence): Comprimento da sequência (seq_len = 128) (seq_len maior aumenta memória quadraticamente (O(T²))

- d_model: Dimensão do embedding (256) (representações vetoriais do código)

## Get Michelle Mesquita’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

A escolha desses hiperparâmetros não foi aleatória, mas baseada em pesquisa e trade-offs. Estudos mostram que dimensões de embedding entre 128–512 são suficientes para capturar relações semânticas básicas.

- n_layer = 4

A profundidade do modelo afeta capacidade de abstração:

- Camadas 1–2: Aprendem padrões locais (tokens, sintaxe básica)

- Camadas 3–4: Aprendem padrões globais (estrutura, contexto)

- Mais de 4: Para modelos pequenos, camadas adicionais têm retorno decrescente e aumentam overfitting

## Por que Usar Heurísticas? Híbrido Deep Learning + Regras

Modelos pequenos treinados com datasets limitados têm dificuldade em generalizar. Eles podem:

- Memorizar padrões: Reconhecer exemplos similares ao treinamento

- Falsos positivos/negativos: Classificar incorretamente código similar mas diferente

Solução híbrida: Combinar aprendizado profundo (embeddings) com heurísticas (regras explícitas):

```
similarity_score = avg_vuln_sim - avg_safe_sim  # Deep learning
keyword_score = vuln_keyword_count - safe_keyword_count  # Heurística
combined_score = normalize(similarity_score) + weight(keyword_score)
```

Vantagens:

1. Heurísticas capturam padrões que o modelo pode perder

2. Regras são interpretáveis (ex: “usa $_GET sem sanitização”)

3. Reduz falsos negativos em casos conhecidos

4. Heurísticas são rápidas (regex, keyword matching)

## Arquivos do Modelo: .pth e .pkl

.pth (PyTorch)

Arquivos .pth contêm os pesos treinados do modelo neural:

```
torch.save(model.state_dict(), "xss_lm_best.pth")  # Salva pesos
model.load_state_dict(torch.load("xss_lm_best.pth"))  # Carrega pesos
```

São tensores (arrays multidimensionais) que representam os parâmetros aprendidos durante o treinamento.

.pkl (Pickle)

Arquivos .pkl são serializações Python usando pickle. No nosso caso, salvamos o vocabulário:

O vocabulário mapeia caracteres para IDs numéricos e vice-versa, necessário para codificar/decodificar texto.

## Fluxo de Trabalho Completo

O processo começa com o treinamento de um modelo Transformer do zero:

1. Carregamento do Dataset: Dataset XSS do Kaggle

2. Criação do Vocabulário: Mapeamento char-level (cada caractere = um token)

3. Treinamento: 10 épocas com AdamW optimizer, loss CrossEntropy

4. Salvamento: Modelo salvo em xss_lm_best.pth, vocabulário em vocab.pkl

![image](https://miro.medium.com/v2/resize:fit:330/1*2fg9efq6psqVKPXJOdmYeg.png)

O processamento desse modelo durou mais ou menos 10 horas. Após isso, utilizei o Streamlit para testarmos a análise do código com um frontend rápido para análise de cada linha, conforme imagem abaixo

![image](https://miro.medium.com/v2/resize:fit:700/1*mhtucct1eD8r9uP1Wgp93g.png)

![image](https://miro.medium.com/v2/resize:fit:700/1*p1hDimSwZjo83C8BpQKrcA.png)

![image](https://miro.medium.com/v2/resize:fit:700/1*Fg7phsaAQtp-azUbGuQIzA.png)

Sobre a última etapa, queria testar o fine-tunning com LoRa (Low-Rank Adaption). Assim, fine-tuning adapta um modelo pré-treinado (TinyLlama) para nossa tarefa específica usando LoRA. TinyLlama já entende linguagem natural e código, herda capacidade linguística do modelo base.

O LoRa utiliza camadas pequenas inseridas no modelo que aprendem tarefa-específica sem modificar pesos originais. Então, ele é um tipo de fine-tuning eficiente com poucos dados

![image](https://miro.medium.com/v2/resize:fit:526/1*6OLXj74K4Fdh_aFdbiPdcw.png)

Para testar esse modelo com fine-tunning, utilizei o ollama pois permite executar modelos LLM localmente de forma simples

exemplo de uso:

```
ollama run xss-fixer "echo $_GET['q'];"
```

No entanto, os resultados não ficaram tão bons quanto o primeiro modelo, provavelmente por ter sido treinado apenas para detectar XSS, sem conhecimento prévio de linguagem natural

![image](https://miro.medium.com/v2/resize:fit:700/1*GYH3C82lfHtaoG4fxzJ7Ew.png)

Espero que tenham gostado dos insights apresentados :)



---
*Original URL: [https://medium.com/@michelleamesquita/mini-gpt-para-xss-8d5ebbe53473?source=search_post---------91-----------------------------------](https://medium.com/@michelleamesquita/mini-gpt-para-xss-8d5ebbe53473?source=search_post---------91-----------------------------------)*
