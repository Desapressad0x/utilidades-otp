#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/stat.h>
#include <string.h>
#include <windows.h>
#include <locale.h>
#include <ntsecapi.h>

void bytes(void *buffer, size_t tamanho) {
    if (!RtlGenRandom(buffer, tamanho)) {
        puts("[x] erro ao gerar os números aleatórios.");
		exit(1);
    }
}

void apagar(const char *arquivo) {
    FILE *arq = fopen(arquivo, "r+b");
    if (arq) {
        struct stat info;
        if (fstat(fileno(arq), &info) == 0) {
            size_t tamanho = info.st_size;
            char *buffer = (char *)malloc(tamanho);
            if (buffer) {
                int num_passes = 7;
                for (int i = 0; i < num_passes; i++) {
                    bytes(buffer, tamanho);
                    fseek(arq, 0, SEEK_SET);
                    fwrite(buffer, 1, tamanho, arq);
                    fflush(arq);
                }
                free(buffer);
            }
        }
        fclose(arq);
        remove(arquivo);
    } else {
        puts("[x] erro ao abrir o arquivo para remoção segura.");
		exit(1);
    }
}

void gerar_arquivo_chave(const char *nome_arquivo, size_t tamanho) {
    FILE *arq_chave = fopen(nome_arquivo, "wb");
    if (arq_chave) {
        char *buffer = (char *)malloc(tamanho);
        if (buffer) {
            bytes(buffer, tamanho);
            fwrite(buffer, 1, tamanho, arq_chave);
            free(buffer);
            printf("[!] arquivo de chave gerado com sucesso: %s", nome_arquivo);
        }
        fclose(arq_chave);
    } else {
        puts("[x] erro ao gerar arquivo de chave");
		exit(1);
    }
}

int main(int argc, char **argv) {
    struct stat info_entrada, info_chave;
    setlocale(LC_ALL, "pt_BR.UTF-8");

    char resposta;
    int chave = 0, dado = 0, resultado = 0, contador = 0;
    FILE *arq_entrada, *arq_saida, *arq_chave;

    if (argc != 4) {
        puts("\n         Utilidades OTP\n");
        printf("            .-\"\"-.\n");
        printf("           / .--. \\\n");
        printf("          / /    \\ \\\n");
        printf("          | |    | |\n");
        printf("          | |.-\"\"-|\n");
        printf("         ///`.::::.`\\\n");
        printf("        ||| ::/  \\:: ;\n");
        printf("        ||; ::\\__/:: ;\n");
        printf("         \\\\ '::::' /\n");
        printf("          `=':-..-'  \n\n\n");
        puts("Copyright (c) 2024 - Desapressado");
        puts("  - Utilize uma chave aleatória e nunca reutilize a mesma chave.");
        puts("  - O arquivo de entrada deve ter o mesmo tamanho da chave em bytes.");
        puts("    * Para verificar o tamanho do arquivo de entrada, rode o programa.");
        puts("    * Caso tenha preguiça, uma chave será gerada para você.");
        puts("  - Para descriptografar, o comando é o mesmo, o arquivo de entrada deve ser o arquivo criptografado.\n");
        printf("  Uso: %s <arquivo_entrada> <arquivo_saida> <arquivo_chave>\n", argv[0]);
        return 0;
    }

    if ((arq_entrada = fopen(argv[1], "rb")) == NULL) {
        puts("[x] erro ao abrir o arquivo de entrada.");
        return -0;
    }

    if (fstat(fileno(arq_entrada), &info_entrada) != 0) {
        puts("[x] erro ao obter informações do arquivo de entrada.");
        fclose(arq_entrada);
        return -1;
    }

    if ((arq_chave = fopen(argv[3], "rb")) == NULL) {
        puts("[x] erro ao abrir o arquivo de chave.");
        fclose(arq_entrada);
        return -2;
    }

    if (fstat(fileno(arq_chave), &info_chave) != 0) {
        puts("[x] erro ao obter informações do arquivo de chave.");
        fclose(arq_chave);
        fclose(arq_entrada);
        return -3;
    }

    if (info_chave.st_size != info_entrada.st_size) {
        printf("[x] o tamanho da chave do arquivo não corresponde ao tamanho do conteúdo do arquivo de entrada.\n");
        printf("  - [*] tamanho do arquivo de entrada: %lld bytes\n", (long long)info_entrada.st_size);

        printf("[?] deseja gerar um novo arquivo de chave com tamanho apropriado? (S/N): ");
        resposta = getchar();
        getchar();

        if (tolower(resposta) == 's') {
            gerar_arquivo_chave(argv[3], info_entrada.st_size);
            fclose(arq_chave);
            arq_chave = fopen(argv[3], "rb");
        } else {
            puts("[x] operação cancelada.");
            fclose(arq_chave);
            fclose(arq_entrada);
            return -4;
        }
    }

    if ((arq_saida = fopen(argv[2], "wb")) == NULL) {
        puts("[x] erro ao abrir o arquivo de saída.");
        fclose(arq_chave);
        fclose(arq_entrada);
        return -5;
    }

    puts("[!] encriptando/desencriptando...");
    while (contador < info_entrada.st_size) {
        chave = fgetc(arq_chave);
        dado = fgetc(arq_entrada);
        if (chave == EOF || dado == EOF) {
            puts("[x] erro durante a leitura dos arquivos.");
            fclose(arq_chave);
            fclose(arq_entrada);
            fclose(arq_saida);
            return -6;
        }
        resultado = (chave ^ dado);
        if (fputc(resultado, arq_saida) == EOF) {
            puts("[x] erro ao escrever no arquivo de saída.");
            fclose(arq_chave);
            fclose(arq_entrada);
            fclose(arq_saida);
            return -7;
        }

        SecureZeroMemory(&chave, sizeof(chave));
        SecureZeroMemory(&dado, sizeof(dado));
        SecureZeroMemory(&resultado, sizeof(resultado));

        contador++;
    }

    fclose(arq_chave);
    fclose(arq_entrada);
    fclose(arq_saida);

    puts("[!] operação de encriptação/desencriptação concluída.");
    printf("[?] deseja apagar o arquivo de entrada com segurança? (S/N): ");
    resposta = getchar();
    getchar();
    if (tolower(resposta) == 's') {
        apagar(argv[1]);
        puts("[!] arquivo de entrada apagado com sucesso.");
    }

    printf("[?] deseja apagar o arquivo de chave com segurança? (S/N): ");
    resposta = getchar();
    getchar();
    if (tolower(resposta) == 's') {
        apagar(argv[3]);
        puts("[!] arquivo de chave apagado com sucesso.");
    }

    return 0;
}
