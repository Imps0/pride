from sklearn import tree

# dataset inicial (mantenha/ajuste conforme seus testes)
features = [[3, 2, 2, 1, 0], [2, 0, 15, 0, 0], [20, 3, 0, 0, 0],
            [0, 0, 2, 0, 0], [0, 0, 2, 0, 5], [0, 0, 0, 0, 0],
            [2, 2, 0, 0, 0], [0, 2, 0, 20, 0], [0, 2, 0, 2, 0],
            [3, 2, 2, 1, 8], [2, 0, 15, 0, 5], [11, 0, 0, 11, 0],
            [0, 10, 0, 2, 30], [2, 10, 3, 1, 0], [0, 40, 40, 0, 30]]
labels = [0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1]

classifying = tree.DecisionTreeClassifier()
classifying.fit(features, labels)


def avaliar(arquivos_criados, arquivos_mods, arquivos_movs, arquivos_delets, arquivos_edits):
    """
    Retorna True se classificador indicar possível ransomware, False caso contrário.
    Fail-safe = False (não interrompe o sistema por exceção).
    """
    try:
        pred = classifying.predict([[arquivos_criados, arquivos_mods, arquivos_movs, arquivos_delets, arquivos_edits]])
        resultado = int(pred[0])
        return resultado == 1
    except Exception as e:
        print(f"[comportamento.avaliar] Erro no classificador: {e}")
        return False
