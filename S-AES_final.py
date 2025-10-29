import sys
import random
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QGroupBox, QLabel, QLineEdit,
                             QPushButton, QTextEdit, QTabWidget, QMessageBox,
                             QGridLayout, QComboBox)
from PyQt5.QtCore import Qt


class SAES:
    """S-AES算法实现类"""

    # S盒和逆S盒
    S_BOX = [
        [0x9, 0x4, 0xA, 0xB],
        [0xD, 0x1, 0x8, 0x5],
        [0x6, 0x2, 0x0, 0x3],
        [0xC, 0xE, 0xF, 0x7]
    ]

    INV_S_BOX = [
        [0xA, 0x5, 0x9, 0xB],
        [0x1, 0x7, 0x8, 0xF],
        [0x6, 0x0, 0x2, 0x3],
        [0xC, 0x4, 0xD, 0xE]
    ]

    # 列混淆矩阵和逆矩阵
    MIX_MATRIX = [[1, 4], [4, 1]]
    INV_MIX_MATRIX = [[9, 2], [2, 9]]

    # RCON常数
    RCON = [0x80, 0x30]

    def __init__(self):
        pass

    def gf_mult(self, a, b):
        """在GF(2^4)上的乘法"""
        if a == 0 or b == 0:
            return 0

        # 使用查找表进行乘法
        mult_table = [
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF],
            [0, 2, 4, 6, 8, 0xA, 0xC, 0xE, 3, 1, 7, 5, 0xB, 9, 0xF, 0xD],
            [0, 3, 6, 5, 0xC, 0xF, 0xA, 9, 0xB, 8, 0xD, 0xE, 7, 4, 1, 2],
            [0, 4, 8, 0xC, 3, 7, 0xB, 0xF, 6, 2, 0xE, 0xA, 5, 1, 0xD, 9],
            [0, 5, 0xA, 0xF, 7, 2, 0xD, 8, 0xE, 0xB, 4, 1, 9, 0xC, 3, 6],
            [0, 6, 0xC, 0xA, 0xB, 0xD, 7, 1, 5, 3, 9, 0xF, 0xE, 8, 2, 4],
            [0, 7, 0xE, 9, 0xF, 8, 1, 6, 0xD, 0xA, 3, 4, 2, 5, 0xC, 0xB],
            [0, 8, 3, 0xB, 6, 0xE, 5, 0xD, 0xC, 4, 0xF, 7, 0xA, 2, 9, 1],
            [0, 9, 1, 8, 2, 0xB, 3, 0xA, 4, 0xD, 5, 0xC, 6, 0xF, 7, 0xE],
            [0, 0xA, 7, 0xD, 0xE, 4, 9, 3, 0xF, 5, 8, 2, 1, 0xB, 6, 0xC],
            [0, 0xB, 5, 0xE, 0xA, 1, 0xF, 4, 7, 0xC, 2, 9, 0xD, 6, 8, 3],
            [0, 0xC, 0xB, 7, 5, 9, 0xE, 2, 0xA, 6, 1, 0xD, 0xF, 3, 4, 8],
            [0, 0xD, 9, 4, 1, 0xC, 8, 5, 2, 0xF, 0xB, 6, 3, 0xE, 0xA, 7],
            [0, 0xE, 0xF, 1, 0xD, 3, 2, 0xC, 9, 7, 6, 8, 4, 0xA, 0xB, 5],
            [0, 0xF, 0xD, 2, 9, 6, 4, 0xB, 1, 0xE, 0xC, 3, 8, 7, 5, 0xA]
        ]

        return mult_table[a][b]

    def key_expansion(self, key):
        """密钥扩展"""
        # 将16位密钥分成两个8位字
        w0 = (key >> 8) & 0xFF
        w1 = key & 0xFF

        # 计算w2
        rot_nib = ((w1 & 0x0F) << 4) | ((w1 & 0xF0) >> 4)
        sub_nib = self.sub_nib(rot_nib, self.S_BOX)
        w2 = w0 ^ self.RCON[0] ^ sub_nib

        # 计算w3
        w3 = w2 ^ w1

        # 计算w4
        rot_nib = ((w3 & 0x0F) << 4) | ((w3 & 0xF0) >> 4)
        sub_nib = self.sub_nib(rot_nib, self.S_BOX)
        w4 = w2 ^ self.RCON[1] ^ sub_nib

        # 计算w5
        w5 = w4 ^ w3

        # 组合成轮密钥
        k0 = (w0 << 8) | w1
        k1 = (w2 << 8) | w3
        k2 = (w4 << 8) | w5

        return [k0, k1, k2]

    def sub_nib(self, byte, s_box):
        """半字节替换"""
        high_nib = (byte >> 4) & 0x0F
        low_nib = byte & 0x0F

        # 从S盒中查找替换值
        high_row = (high_nib >> 2) & 0x03
        high_col = high_nib & 0x03
        high_sub = s_box[high_row][high_col]

        low_row = (low_nib >> 2) & 0x03
        low_col = low_nib & 0x03
        low_sub = s_box[low_row][low_col]

        return (high_sub << 4) | low_sub

    def shift_row(self, state):
        """行移位"""
        # 将16位状态转换为2x2矩阵
        s00 = (state >> 12) & 0x0F
        s01 = (state >> 8) & 0x0F
        s10 = (state >> 4) & 0x0F
        s11 = state & 0x0F

        # 第二行循环左移一个半字节
        s10, s11 = s11, s10

        # 重新组合状态
        return (s00 << 12) | (s01 << 8) | (s10 << 4) | s11

    def mix_columns(self, state, mix_matrix):
        """列混淆"""
        # 将16位状态转换为2x2矩阵
        s00 = (state >> 12) & 0x0F
        s01 = (state >> 8) & 0x0F
        s10 = (state >> 4) & 0x0F
        s11 = state & 0x0F

        # 矩阵乘法
        s00_new = self.gf_mult(mix_matrix[0][0], s00) ^ self.gf_mult(mix_matrix[0][1], s10)
        s01_new = self.gf_mult(mix_matrix[0][0], s01) ^ self.gf_mult(mix_matrix[0][1], s11)
        s10_new = self.gf_mult(mix_matrix[1][0], s00) ^ self.gf_mult(mix_matrix[1][1], s10)
        s11_new = self.gf_mult(mix_matrix[1][0], s01) ^ self.gf_mult(mix_matrix[1][1], s11)

        # 重新组合状态
        return (s00_new << 12) | (s01_new << 8) | (s10_new << 4) | s11_new

    def add_round_key(self, state, round_key):
        """轮密钥加"""
        return state ^ round_key

    def encrypt(self, plaintext, key):
        """加密函数"""
        # 密钥扩展
        round_keys = self.key_expansion(key)

        # 第0轮：轮密钥加
        state = self.add_round_key(plaintext, round_keys[0])

        # 第1轮：完整轮
        state = self.sub_nib(state, self.S_BOX)
        state = self.shift_row(state)
        state = self.mix_columns(state, self.MIX_MATRIX)
        state = self.add_round_key(state, round_keys[1])

        # 第2轮：简化轮
        state = self.sub_nib(state, self.S_BOX)
        state = self.shift_row(state)
        state = self.add_round_key(state, round_keys[2])

        return state

    def decrypt(self, ciphertext, key):
        """解密函数 - 修复后的版本"""
        # 密钥扩展
        round_keys = self.key_expansion(key)

        # 第0轮：轮密钥加（使用K2）
        state = self.add_round_key(ciphertext, round_keys[2])

        # 第1轮：逆行移位 -> 逆半字节替换 -> 轮密钥加（使用K1）-> 逆列混淆
        state = self.shift_row(state)  # 逆行移位
        state = self.sub_nib(state, self.INV_S_BOX)  # 逆半字节替换
        state = self.add_round_key(state, round_keys[1])  # 轮密钥加
        state = self.mix_columns(state, self.INV_MIX_MATRIX)  # 逆列混淆

        # 第2轮：逆行移位 -> 逆半字节替换 -> 轮密钥加（使用K0）
        state = self.shift_row(state)  # 逆行移位
        state = self.sub_nib(state, self.INV_S_BOX)  # 逆半字节替换
        state = self.add_round_key(state, round_keys[0])  # 轮密钥加

        return state


class DoubleSAES:
    """双重S-AES加密"""

    def __init__(self):
        self.saes = SAES()

    def encrypt(self, plaintext, key):
        """双重加密"""
        key1 = (key >> 16) & 0xFFFF
        key2 = key & 0xFFFF

        # 第一轮加密
        intermediate = self.saes.encrypt(plaintext, key1)
        # 第二轮加密
        ciphertext = self.saes.encrypt(intermediate, key2)

        return ciphertext

    def decrypt(self, ciphertext, key):
        """双重解密"""
        key1 = (key >> 16) & 0xFFFF
        key2 = key & 0xFFFF

        # 第一轮解密
        intermediate = self.saes.decrypt(ciphertext, key2)
        # 第二轮解密
        plaintext = self.saes.decrypt(intermediate, key1)

        return plaintext


class TripleSAES:
    """三重S-AES加密"""

    def __init__(self):
        self.saes = SAES()

    def encrypt_32bit(self, plaintext, key):
        """使用32位密钥的三重加密"""
        key1 = (key >> 16) & 0xFFFF
        key2 = key & 0xFFFF

        # 加密-解密-加密模式
        cipher1 = self.saes.encrypt(plaintext, key1)
        cipher2 = self.saes.decrypt(cipher1, key2)
        cipher3 = self.saes.encrypt(cipher2, key1)

        return cipher3

    def decrypt_32bit(self, ciphertext, key):
        """使用32位密钥的三重解密"""
        key1 = (key >> 16) & 0xFFFF
        key2 = key & 0xFFFF

        # 解密-加密-解密模式
        plain1 = self.saes.decrypt(ciphertext, key1)
        plain2 = self.saes.encrypt(plain1, key2)
        plain3 = self.saes.decrypt(plain2, key1)

        return plain3

    def encrypt_48bit(self, plaintext, key):
        """使用48位密钥的三重加密"""
        key1 = (key >> 32) & 0xFFFF
        key2 = (key >> 16) & 0xFFFF
        key3 = key & 0xFFFF

        # 加密-加密-加密模式
        cipher1 = self.saes.encrypt(plaintext, key1)
        cipher2 = self.saes.encrypt(cipher1, key2)
        cipher3 = self.saes.encrypt(cipher2, key3)

        return cipher3

    def decrypt_48bit(self, ciphertext, key):
        """使用48位密钥的三重解密"""
        key1 = (key >> 32) & 0xFFFF
        key2 = (key >> 16) & 0xFFFF
        key3 = key & 0xFFFF

        # 解密-解密-解密模式
        plain1 = self.saes.decrypt(ciphertext, key3)
        plain2 = self.saes.decrypt(plain1, key2)
        plain3 = self.saes.decrypt(plain2, key1)

        return plain3


class CBCMode:
    """CBC工作模式"""

    def __init__(self):
        self.saes = SAES()

    def encrypt(self, plaintext_blocks, key, iv):
        """CBC模式加密"""
        ciphertext_blocks = []
        prev_block = iv

        for block in plaintext_blocks:
            # 与前一个密文块异或
            xored_block = block ^ prev_block
            # 加密
            encrypted_block = self.saes.encrypt(xored_block, key)
            ciphertext_blocks.append(encrypted_block)
            prev_block = encrypted_block

        return ciphertext_blocks

    def decrypt(self, ciphertext_blocks, key, iv):
        """CBC模式解密"""
        plaintext_blocks = []
        prev_block = iv

        for block in ciphertext_blocks:
            # 解密
            decrypted_block = self.saes.decrypt(block, key)
            # 与前一个密文块异或
            xored_block = decrypted_block ^ prev_block
            plaintext_blocks.append(xored_block)
            prev_block = block

        return plaintext_blocks


class MeetInTheMiddleAttack:
    """中间相遇攻击"""

    def __init__(self):
        self.saes = SAES()

    def generate_encryption_table(self, plaintext):
        """生成加密表：K1 -> 中间值"""
        encryption_table = {}
        # 为了演示，我们只遍历部分密钥空间（实际应该遍历0-65535）
        # 这里遍历0-255以加快演示速度
        for key1 in range(0x100):  # 只遍历前256个密钥用于演示
            intermediate = self.saes.encrypt(plaintext, key1)
            encryption_table[intermediate] = key1
        return encryption_table

    def generate_decryption_table(self, ciphertext):
        """生成解密表：K2 -> 中间值"""
        decryption_table = {}
        # 为了演示，我们只遍历部分密钥空间
        for key2 in range(0x100):  # 只遍历前256个密钥用于演示
            intermediate = self.saes.decrypt(ciphertext, key2)
            decryption_table[intermediate] = key2
        return decryption_table

    def attack_single_pair(self, plaintext, ciphertext):
        """对单个明密文对进行中间相遇攻击"""
        print("生成加密表...")
        enc_table = self.generate_encryption_table(plaintext)

        print("生成解密表...")
        dec_table = self.generate_decryption_table(ciphertext)

        # 寻找匹配的中间值
        possible_keys = []
        for intermediate, key1 in enc_table.items():
            if intermediate in dec_table:
                key2 = dec_table[intermediate]
                full_key = (key1 << 16) | key2
                possible_keys.append((key1, key2, full_key))

        return possible_keys

    def attack_multiple_pairs(self, pairs):
        """对多个明密文对进行中间相遇攻击，提高准确性"""
        if not pairs:
            return []

        # 对第一个明密文对进行攻击
        first_plain, first_cipher = pairs[0]
        candidate_keys = self.attack_single_pair(first_plain, first_cipher)

        # 用其他明密文对验证候选密钥
        if len(pairs) > 1:
            verified_keys = []
            for k1, k2, full_key in candidate_keys:
                valid = True
                for plain, cipher in pairs[1:]:
                    test_cipher = self.saes.encrypt(
                        self.saes.encrypt(plain, k1), k2
                    )
                    if test_cipher != cipher:
                        valid = False
                        break
                if valid:
                    verified_keys.append((k1, k2, full_key))
            return verified_keys

        return candidate_keys


class SAESGUI(QMainWindow):
    """S-AES图形用户界面"""

    def __init__(self):
        super().__init__()
        self.saes = SAES()
        self.double_saes = DoubleSAES()
        self.triple_saes = TripleSAES()
        self.cbc_mode = CBCMode()
        self.mitm_attack = MeetInTheMiddleAttack()
        self.init_ui()

    def init_ui(self):
        """初始化用户界面"""
        self.setWindowTitle('S-AES加解密系统')
        self.setGeometry(100, 100, 900, 700)

        # 创建主窗口部件和布局
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # 创建标签页
        tab_widget = QTabWidget()
        main_layout.addWidget(tab_widget)

        # 基本测试标签页
        basic_tab = self.create_basic_tab()
        tab_widget.addTab(basic_tab, "基本测试")

        # ASCII加解密标签页
        ascii_tab = self.create_ascii_tab()
        tab_widget.addTab(ascii_tab, "ASCII加解密")

        # 多重加密标签页
        multi_tab = self.create_multi_tab()
        tab_widget.addTab(multi_tab, "多重加密")

        # CBC模式标签页
        cbc_tab = self.create_cbc_tab()
        tab_widget.addTab(cbc_tab, "CBC模式")

        # 密码分析标签页
        attack_tab = self.create_attack_tab()
        tab_widget.addTab(attack_tab, "密码分析")

    def create_basic_tab(self):
        """创建基本测试标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # 输入组
        input_group = QGroupBox("输入")
        input_layout = QGridLayout(input_group)

        input_layout.addWidget(QLabel("明文(4位十六进制):"), 0, 0)
        self.plaintext_edit = QLineEdit()
        self.plaintext_edit.setPlaceholderText("输入4位十六进制数，如: 6F6B")
        input_layout.addWidget(self.plaintext_edit, 0, 1)

        input_layout.addWidget(QLabel("密钥(4位十六进制):"), 1, 0)
        self.key_edit = QLineEdit()
        self.key_edit.setPlaceholderText("输入4位十六进制数，如: A73B")
        input_layout.addWidget(self.key_edit, 1, 1)

        layout.addWidget(input_group)

        # 按钮组
        button_layout = QHBoxLayout()

        encrypt_btn = QPushButton("加密")
        encrypt_btn.clicked.connect(self.basic_encrypt)
        button_layout.addWidget(encrypt_btn)

        decrypt_btn = QPushButton("解密")
        decrypt_btn.clicked.connect(self.basic_decrypt)
        button_layout.addWidget(decrypt_btn)

        clear_btn = QPushButton("清空")
        clear_btn.clicked.connect(self.clear_basic)
        button_layout.addWidget(clear_btn)

        layout.addLayout(button_layout)

        # 输出组
        output_group = QGroupBox("输出")
        output_layout = QVBoxLayout(output_group)

        self.basic_output = QTextEdit()
        self.basic_output.setReadOnly(True)
        output_layout.addWidget(self.basic_output)

        layout.addWidget(output_group)

        return widget

    def create_ascii_tab(self):
        """创建ASCII加解密标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # 输入组
        input_group = QGroupBox("输入")
        input_layout = QGridLayout(input_group)

        input_layout.addWidget(QLabel("ASCII文本:"), 0, 0)
        self.ascii_input = QTextEdit()
        self.ascii_input.setMaximumHeight(80)
        input_layout.addWidget(self.ascii_input, 0, 1)

        input_layout.addWidget(QLabel("密钥(4位十六进制):"), 1, 0)
        self.ascii_key = QLineEdit()
        self.ascii_key.setPlaceholderText("输入4位十六进制数")
        input_layout.addWidget(self.ascii_key, 1, 1)

        layout.addWidget(input_group)

        # 按钮组
        button_layout = QHBoxLayout()

        ascii_encrypt_btn = QPushButton("ASCII加密")
        ascii_encrypt_btn.clicked.connect(self.ascii_encrypt)
        button_layout.addWidget(ascii_encrypt_btn)

        ascii_decrypt_btn = QPushButton("ASCII解密")
        ascii_decrypt_btn.clicked.connect(self.ascii_decrypt)
        button_layout.addWidget(ascii_decrypt_btn)

        clear_ascii_btn = QPushButton("清空")
        clear_ascii_btn.clicked.connect(self.clear_ascii)
        button_layout.addWidget(clear_ascii_btn)

        layout.addLayout(button_layout)

        # 输出组
        output_group = QGroupBox("输出")
        output_layout = QVBoxLayout(output_group)

        self.ascii_output = QTextEdit()
        self.ascii_output.setReadOnly(True)
        output_layout.addWidget(self.ascii_output)

        layout.addWidget(output_group)

        return widget

    def create_multi_tab(self):
        """创建多重加密标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # 加密类型选择
        type_group = QGroupBox("加密类型")
        type_layout = QHBoxLayout(type_group)

        self.encryption_type = QComboBox()
        self.encryption_type.addItems(
            ["双重加密(8位十六进制密钥)", "三重加密-8位十六进制密钥", "三重加密-12位十六进制密钥"])
        type_layout.addWidget(QLabel("选择加密类型:"))
        type_layout.addWidget(self.encryption_type)

        layout.addWidget(type_group)

        # 输入组
        input_group = QGroupBox("输入")
        input_layout = QGridLayout(input_group)

        input_layout.addWidget(QLabel("明文(4位十六进制):"), 0, 0)
        self.multi_plaintext = QLineEdit()
        self.multi_plaintext.setPlaceholderText("输入4位十六进制数")
        input_layout.addWidget(self.multi_plaintext, 0, 1)

        input_layout.addWidget(QLabel("密钥:"), 1, 0)
        self.multi_key = QLineEdit()
        self.multi_key.setPlaceholderText("根据加密类型输入8位或12位十六进制数")
        input_layout.addWidget(self.multi_key, 1, 1)

        layout.addWidget(input_group)

        # 按钮组
        button_layout = QHBoxLayout()

        multi_encrypt_btn = QPushButton("多重加密")
        multi_encrypt_btn.clicked.connect(self.multi_encrypt)
        button_layout.addWidget(multi_encrypt_btn)

        multi_decrypt_btn = QPushButton("多重解密")
        multi_decrypt_btn.clicked.connect(self.multi_decrypt)
        button_layout.addWidget(multi_decrypt_btn)

        clear_multi_btn = QPushButton("清空")
        clear_multi_btn.clicked.connect(self.clear_multi)
        button_layout.addWidget(clear_multi_btn)

        layout.addLayout(button_layout)

        # 输出组
        output_group = QGroupBox("输出")
        output_layout = QVBoxLayout(output_group)

        self.multi_output = QTextEdit()
        self.multi_output.setReadOnly(True)
        output_layout.addWidget(self.multi_output)

        layout.addWidget(output_group)

        return widget

    def create_cbc_tab(self):
        """创建CBC模式标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # 输入组
        input_group = QGroupBox("输入")
        input_layout = QGridLayout(input_group)

        input_layout.addWidget(QLabel("明文(多个4位十六进制块):"), 0, 0)
        self.cbc_plaintext = QTextEdit()
        self.cbc_plaintext.setMaximumHeight(60)
        self.cbc_plaintext.setPlaceholderText("输入多个4位十六进制数，用空格分隔")
        input_layout.addWidget(self.cbc_plaintext, 0, 1)

        input_layout.addWidget(QLabel("密钥(4位十六进制):"), 1, 0)
        self.cbc_key = QLineEdit()
        self.cbc_key.setPlaceholderText("输入4位十六进制数")
        input_layout.addWidget(self.cbc_key, 1, 1)

        input_layout.addWidget(QLabel("初始向量(4位十六进制):"), 2, 0)
        self.cbc_iv = QLineEdit()
        self.cbc_iv.setPlaceholderText("输入4位十六进制数")
        input_layout.addWidget(self.cbc_iv, 2, 1)

        layout.addWidget(input_group)

        # 按钮组
        button_layout = QHBoxLayout()

        cbc_encrypt_btn = QPushButton("CBC加密")
        cbc_encrypt_btn.clicked.connect(self.cbc_encrypt)
        button_layout.addWidget(cbc_encrypt_btn)

        cbc_decrypt_btn = QPushButton("CBC解密")
        cbc_decrypt_btn.clicked.connect(self.cbc_decrypt)
        button_layout.addWidget(cbc_decrypt_btn)

        tamper_btn = QPushButton("篡改测试")
        tamper_btn.clicked.connect(self.tamper_test)
        button_layout.addWidget(tamper_btn)

        clear_cbc_btn = QPushButton("清空")
        clear_cbc_btn.clicked.connect(self.clear_cbc)
        button_layout.addWidget(clear_cbc_btn)

        layout.addLayout(button_layout)

        # 输出组
        output_group = QGroupBox("输出")
        output_layout = QVBoxLayout(output_group)

        self.cbc_output = QTextEdit()
        self.cbc_output.setReadOnly(True)
        output_layout.addWidget(self.cbc_output)

        layout.addWidget(output_group)

        return widget

    def create_attack_tab(self):
        """创建密码分析标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # 攻击类型选择
        attack_group = QGroupBox("攻击类型")
        attack_layout = QHBoxLayout(attack_group)

        self.attack_type = QComboBox()
        self.attack_type.addItems(["中间相遇攻击(双重加密)"])
        attack_layout.addWidget(QLabel("选择攻击类型:"))
        attack_layout.addWidget(self.attack_type)

        layout.addWidget(attack_group)

        # 输入组
        input_group = QGroupBox("已知明密文对")
        input_layout = QVBoxLayout(input_group)

        # 明密文对输入
        pair_layout = QHBoxLayout()
        pair_layout.addWidget(QLabel("明文:"))
        self.attack_plaintext = QLineEdit()
        self.attack_plaintext.setPlaceholderText("4位十六进制")
        pair_layout.addWidget(self.attack_plaintext)

        pair_layout.addWidget(QLabel("密文:"))
        self.attack_ciphertext = QLineEdit()
        self.attack_ciphertext.setPlaceholderText("4位十六进制")
        pair_layout.addWidget(self.attack_ciphertext)

        add_pair_btn = QPushButton("添加对")
        add_pair_btn.clicked.connect(self.add_attack_pair)
        pair_layout.addWidget(add_pair_btn)

        input_layout.addLayout(pair_layout)

        # 已添加的明密文对列表
        self.attack_pairs_list = QTextEdit()
        self.attack_pairs_list.setMaximumHeight(100)
        self.attack_pairs_list.setReadOnly(True)
        input_layout.addWidget(self.attack_pairs_list)

        layout.addWidget(input_group)

        # 按钮组
        button_layout = QHBoxLayout()

        attack_btn = QPushButton("开始攻击")
        attack_btn.clicked.connect(self.perform_attack)
        button_layout.addWidget(attack_btn)

        clear_attack_btn = QPushButton("清空")
        clear_attack_btn.clicked.connect(self.clear_attack)
        button_layout.addWidget(clear_attack_btn)

        layout.addLayout(button_layout)

        # 输出组
        output_group = QGroupBox("攻击结果")
        output_layout = QVBoxLayout(output_group)

        self.attack_output = QTextEdit()
        self.attack_output.setReadOnly(True)
        output_layout.addWidget(self.attack_output)

        layout.addWidget(output_group)

        return widget

    def validate_hex(self, text, length):
        """验证十六进制输入"""
        if len(text) != length:
            return False
        for char in text:
            if not char.lower() in '0123456789abcdef':
                return False
        return True

    def hex_to_int(self, hex_str):
        """十六进制字符串转整数"""
        return int(hex_str, 16)

    def int_to_binary(self, number, length):
        """整数转二进制字符串"""
        return format(number, f'0{length}b')

    def int_to_hex(self, number, length):
        """整数转十六进制字符串"""
        return format(number, f'0{length}X')

    def basic_encrypt(self):
        """基本加密"""
        plaintext = self.plaintext_edit.text().strip()
        key = self.key_edit.text().strip()

        if not self.validate_hex(plaintext, 4):
            QMessageBox.warning(self, "错误", "明文必须是4位十六进制数")
            return

        if not self.validate_hex(key, 4):
            QMessageBox.warning(self, "错误", "密钥必须是4位十六进制数")
            return

        plaintext_int = self.hex_to_int(plaintext)
        key_int = self.hex_to_int(key)

        ciphertext = self.saes.encrypt(plaintext_int, key_int)
        ciphertext_hex = self.int_to_hex(ciphertext, 4)
        ciphertext_bin = self.int_to_binary(ciphertext, 16)

        output = f"明文: {plaintext}\n"
        output += f"密钥: {key}\n"
        output += f"密文(十六进制): {ciphertext_hex}\n"
        output += f"密文(二进制): {ciphertext_bin}"

        self.basic_output.setText(output)

    def basic_decrypt(self):
        """基本解密"""
        ciphertext = self.plaintext_edit.text().strip()
        key = self.key_edit.text().strip()

        if not self.validate_hex(ciphertext, 4):
            QMessageBox.warning(self, "错误", "密文必须是4位十六进制数")
            return

        if not self.validate_hex(key, 4):
            QMessageBox.warning(self, "错误", "密钥必须是4位十六进制数")
            return

        ciphertext_int = self.hex_to_int(ciphertext)
        key_int = self.hex_to_int(key)

        plaintext = self.saes.decrypt(ciphertext_int, key_int)
        plaintext_hex = self.int_to_hex(plaintext, 4)
        plaintext_bin = self.int_to_binary(plaintext, 16)

        output = f"密文: {ciphertext}\n"
        output += f"密钥: {key}\n"
        output += f"明文(十六进制): {plaintext_hex}\n"
        output += f"明文(二进制): {plaintext_bin}"

        self.basic_output.setText(output)

    def ascii_encrypt(self):
        """ASCII加密"""
        text = self.ascii_input.toPlainText().strip()
        key = self.ascii_key.text().strip()

        if not text:
            QMessageBox.warning(self, "错误", "请输入要加密的文本")
            return

        if not self.validate_hex(key, 4):
            QMessageBox.warning(self, "错误", "密钥必须是4位十六进制数")
            return

        key_int = self.hex_to_int(key)

        # 将文本转换为字节
        text_bytes = text.encode('ascii')

        # 分组处理（2字节一组）
        blocks = []
        for i in range(0, len(text_bytes), 2):
            if i + 1 < len(text_bytes):
                block = (text_bytes[i] << 8) | text_bytes[i + 1]
            else:
                block = (text_bytes[i] << 8) | 0x00  # 填充零
            blocks.append(block)

        # 加密每个块
        encrypted_blocks = []
        for block in blocks:
            encrypted_block = self.saes.encrypt(block, key_int)
            encrypted_blocks.append(encrypted_block)

        # 转换为字符串
        encrypted_bytes = bytearray()
        for block in encrypted_blocks:
            encrypted_bytes.append((block >> 8) & 0xFF)
            encrypted_bytes.append(block & 0xFF)

        encrypted_text = encrypted_bytes.decode('latin-1')  # 使用latin-1编码保留所有字节值

        output = f"原始文本: {text}\n"
        output += f"密钥: {key}\n"
        output += f"加密后文本: {encrypted_text}\n"
        output += f"加密块(十六进制): {[self.int_to_hex(b, 4) for b in encrypted_blocks]}"

        self.ascii_output.setText(output)

    def ascii_decrypt(self):
        """ASCII解密"""
        text = self.ascii_input.toPlainText().strip()
        key = self.ascii_key.text().strip()

        if not text:
            QMessageBox.warning(self, "错误", "请输入要解密的文本")
            return

        if not self.validate_hex(key, 4):
            QMessageBox.warning(self, "错误", "密钥必须是4位十六进制数")
            return

        key_int = self.hex_to_int(key)

        # 将文本转换为字节
        try:
            text_bytes = text.encode('latin-1')
        except:
            QMessageBox.warning(self, "错误", "无效的加密文本格式")
            return

        # 分组处理（2字节一组）
        blocks = []
        for i in range(0, len(text_bytes), 2):
            if i + 1 < len(text_bytes):
                block = (text_bytes[i] << 8) | text_bytes[i + 1]
            else:
                QMessageBox.warning(self, "错误", "加密文本长度不正确")
                return
            blocks.append(block)

        # 解密每个块
        decrypted_blocks = []
        for block in blocks:
            decrypted_block = self.saes.decrypt(block, key_int)
            decrypted_blocks.append(decrypted_block)

        # 转换为ASCII字符串
        decrypted_bytes = bytearray()
        for block in decrypted_blocks:
            decrypted_bytes.append((block >> 8) & 0xFF)
            decrypted_bytes.append(block & 0xFF)

        # 移除填充的零
        while decrypted_bytes and decrypted_bytes[-1] == 0:
            decrypted_bytes.pop()

        try:
            decrypted_text = decrypted_bytes.decode('ascii')
        except:
            decrypted_text = "无法解码为ASCII（可能使用了错误的密钥）"

        output = f"加密文本: {text}\n"
        output += f"密钥: {key}\n"
        output += f"解密后文本: {decrypted_text}\n"
        output += f"解密块(十六进制): {[self.int_to_hex(b, 4) for b in decrypted_blocks]}"

        self.ascii_output.setText(output)

    def multi_encrypt(self):
        """多重加密"""
        plaintext = self.multi_plaintext.text().strip()
        key = self.multi_key.text().strip()
        encryption_type = self.encryption_type.currentIndex()

        if not self.validate_hex(plaintext, 4):
            QMessageBox.warning(self, "错误", "明文必须是4位十六进制数")
            return

        plaintext_int = self.hex_to_int(plaintext)

        if encryption_type == 0:  # 双重加密
            if not self.validate_hex(key, 8):
                QMessageBox.warning(self, "错误", "密钥必须是8位十六进制数")
                return
            key_int = self.hex_to_int(key)
            ciphertext = self.double_saes.encrypt(plaintext_int, key_int)
        elif encryption_type == 1:  # 三重加密-32位(8位十六进制)
            if not self.validate_hex(key, 8):
                QMessageBox.warning(self, "错误", "密钥必须是8位十六进制数")
                return
            key_int = self.hex_to_int(key)
            ciphertext = self.triple_saes.encrypt_32bit(plaintext_int, key_int)
        else:  # 三重加密-48位(12位十六进制)
            if not self.validate_hex(key, 12):
                QMessageBox.warning(self, "错误", "密钥必须是12位十六进制数")
                return
            key_int = self.hex_to_int(key)
            ciphertext = self.triple_saes.encrypt_48bit(plaintext_int, key_int)

        ciphertext_hex = self.int_to_hex(ciphertext, 4)
        ciphertext_bin = self.int_to_binary(ciphertext, 16)

        output = f"加密类型: {self.encryption_type.currentText()}\n"
        output += f"明文: {plaintext}\n"
        output += f"密钥: {key}\n"
        output += f"密文(十六进制): {ciphertext_hex}\n"
        output += f"密文(二进制): {ciphertext_bin}"

        self.multi_output.setText(output)

    def multi_decrypt(self):
        """多重解密"""
        ciphertext = self.multi_plaintext.text().strip()
        key = self.multi_key.text().strip()
        encryption_type = self.encryption_type.currentIndex()

        if not self.validate_hex(ciphertext, 4):
            QMessageBox.warning(self, "错误", "密文必须是4位十六进制数")
            return

        ciphertext_int = self.hex_to_int(ciphertext)

        if encryption_type == 0:  # 双重加密
            if not self.validate_hex(key, 8):
                QMessageBox.warning(self, "错误", "密钥必须是8位十六进制数")
                return
            key_int = self.hex_to_int(key)
            plaintext = self.double_saes.decrypt(ciphertext_int, key_int)
        elif encryption_type == 1:  # 三重加密-32位
            if not self.validate_hex(key, 8):
                QMessageBox.warning(self, "错误", "密钥必须是8位十六进制数")
                return
            key_int = self.hex_to_int(key)
            plaintext = self.triple_saes.decrypt_32bit(ciphertext_int, key_int)
        else:  # 三重加密-48位
            if not self.validate_hex(key, 12):
                QMessageBox.warning(self, "错误", "密钥必须是12位十六进制数")
                return
            key_int = self.hex_to_int(key)
            plaintext = self.triple_saes.decrypt_48bit(ciphertext_int, key_int)

        plaintext_hex = self.int_to_hex(plaintext, 4)
        plaintext_bin = self.int_to_binary(plaintext, 16)

        output = f"加密类型: {self.encryption_type.currentText()}\n"
        output += f"密文: {ciphertext}\n"
        output += f"密钥: {key}\n"
        output += f"明文(十六进制): {plaintext_hex}\n"
        output += f"明文(二进制): {plaintext_bin}"

        self.multi_output.setText(output)

    def cbc_encrypt(self):
        """CBC模式加密"""
        plaintext_text = self.cbc_plaintext.toPlainText().strip()
        key = self.cbc_key.text().strip()
        iv = self.cbc_iv.text().strip()

        if not plaintext_text:
            QMessageBox.warning(self, "错误", "请输入明文块")
            return

        if not self.validate_hex(key, 4):
            QMessageBox.warning(self, "错误", "密钥必须是4位十六进制数")
            return

        if not self.validate_hex(iv, 4):
            QMessageBox.warning(self, "错误", "初始向量必须是4位十六进制数")
            return

        # 解析明文块
        plaintext_blocks = []
        for block_str in plaintext_text.split():
            if not self.validate_hex(block_str, 4):
                QMessageBox.warning(self, "错误", f"明文块 '{block_str}' 必须是4位十六进制数")
                return
            plaintext_blocks.append(self.hex_to_int(block_str))

        key_int = self.hex_to_int(key)
        iv_int = self.hex_to_int(iv)

        # CBC加密
        ciphertext_blocks = self.cbc_mode.encrypt(plaintext_blocks, key_int, iv_int)

        output = f"明文块(十六进制): {[self.int_to_hex(b, 4) for b in plaintext_blocks]}\n"
        output += f"密钥: {key}\n"
        output += f"初始向量: {iv}\n"
        output += f"密文块(十六进制): {[self.int_to_hex(b, 4) for b in ciphertext_blocks]}"

        self.cbc_output.setText(output)

    def cbc_decrypt(self):
        """CBC模式解密"""
        ciphertext_text = self.cbc_plaintext.toPlainText().strip()
        key = self.cbc_key.text().strip()
        iv = self.cbc_iv.text().strip()

        if not ciphertext_text:
            QMessageBox.warning(self, "错误", "请输入密文块")
            return

        if not self.validate_hex(key, 4):
            QMessageBox.warning(self, "错误", "密钥必须是4位十六进制数")
            return

        if not self.validate_hex(iv, 4):
            QMessageBox.warning(self, "错误", "初始向量必须是4位十六进制数")
            return

        # 解析密文块
        ciphertext_blocks = []
        for block_str in ciphertext_text.split():
            if not self.validate_hex(block_str, 4):
                QMessageBox.warning(self, "错误", f"密文块 '{block_str}' 必须是4位十六进制数")
                return
            ciphertext_blocks.append(self.hex_to_int(block_str))

        key_int = self.hex_to_int(key)
        iv_int = self.hex_to_int(iv)

        # CBC解密
        plaintext_blocks = self.cbc_mode.decrypt(ciphertext_blocks, key_int, iv_int)

        output = f"密文块(十六进制): {[self.int_to_hex(b, 4) for b in ciphertext_blocks]}\n"
        output += f"密钥: {key}\n"
        output += f"初始向量: {iv}\n"
        output += f"明文块(十六进制): {[self.int_to_hex(b, 4) for b in plaintext_blocks]}"

        self.cbc_output.setText(output)

    def tamper_test(self):
        """篡改测试"""
        ciphertext_text = self.cbc_plaintext.toPlainText().strip()
        key = self.cbc_key.text().strip()
        iv = self.cbc_iv.text().strip()

        if not ciphertext_text:
            QMessageBox.warning(self, "错误", "请输入密文块")
            return

        if not self.validate_hex(key, 4):
            QMessageBox.warning(self, "错误", "密钥必须是4位十六进制数")
            return

        if not self.validate_hex(iv, 4):
            QMessageBox.warning(self, "错误", "初始向量必须是4位十六进制数")
            return

        # 解析密文块
        ciphertext_blocks = []
        for block_str in ciphertext_text.split():
            if not self.validate_hex(block_str, 4):
                QMessageBox.warning(self, "错误", f"密文块 '{block_str}' 必须是4位十六进制数")
                return
            ciphertext_blocks.append(self.hex_to_int(block_str))

        if len(ciphertext_blocks) < 2:
            QMessageBox.warning(self, "错误", "需要至少2个密文块进行篡改测试")
            return

        key_int = self.hex_to_int(key)
        iv_int = self.hex_to_int(iv)

        # 正常解密
        normal_plaintext = self.cbc_mode.decrypt(ciphertext_blocks, key_int, iv_int)

        # 篡改第二个密文块
        tampered_blocks = ciphertext_blocks.copy()
        tampered_blocks[1] ^= 0xFFFF  # 翻转所有位

        # 篡改后解密
        tampered_plaintext = self.cbc_mode.decrypt(tampered_blocks, key_int, iv_int)

        output = "=== 篡改测试 ===\n\n"
        output += f"原始密文块(十六进制): {[self.int_to_hex(b, 4) for b in ciphertext_blocks]}\n"
        output += f"篡改后密文块(十六进制): {[self.int_to_hex(b, 4) for b in tampered_blocks]}\n\n"
        output += f"正常解密结果(十六进制): {[self.int_to_hex(b, 4) for b in normal_plaintext]}\n"
        output += f"篡改后解密结果(十六进制): {[self.int_to_hex(b, 4) for b in tampered_plaintext]}\n\n"
        output += "注意：在CBC模式下，篡改一个密文块会影响对应的明文块和下一个明文块"

        self.cbc_output.setText(output)

    def add_attack_pair(self):
        """添加明密文对"""
        plaintext = self.attack_plaintext.text().strip()
        ciphertext = self.attack_ciphertext.text().strip()

        if not self.validate_hex(plaintext, 4):
            QMessageBox.warning(self, "错误", "明文必须是4位十六进制数")
            return

        if not self.validate_hex(ciphertext, 4):
            QMessageBox.warning(self, "错误", "密文必须是4位十六进制数")
            return

        current_text = self.attack_pairs_list.toPlainText()
        new_text = f"{plaintext} -> {ciphertext}"
        if current_text:
            self.attack_pairs_list.setText(current_text + "\n" + new_text)
        else:
            self.attack_pairs_list.setText(new_text)

        self.attack_plaintext.clear()
        self.attack_ciphertext.clear()

    def perform_attack(self):
        """执行中间相遇攻击"""
        pairs_text = self.attack_pairs_list.toPlainText().strip()
        if not pairs_text:
            QMessageBox.warning(self, "错误", "请至少添加一个明密文对")
            return

        # 解析明密文对
        pairs = []
        for line in pairs_text.split('\n'):
            if '->' in line:
                plain_hex, cipher_hex = line.split('->')
                plain = self.hex_to_int(plain_hex.strip())
                cipher = self.hex_to_int(cipher_hex.strip())
                pairs.append((plain, cipher))

        if not pairs:
            QMessageBox.warning(self, "错误", "没有有效的明密文对")
            return

        # 显示进度
        self.attack_output.setText("正在进行中间相遇攻击...\n这可能需要一些时间...")
        QApplication.processEvents()  # 更新界面

        # 执行攻击
        attack = MeetInTheMiddleAttack()
        possible_keys = attack.attack_multiple_pairs(pairs)

        # 显示结果
        output = f"已知明密文对: {len(pairs)} 对\n"
        output += f"找到的可能密钥: {len(possible_keys)} 个\n\n"

        if possible_keys:
            output += "可能的密钥对 (K1, K2):\n"
            for i, (k1, k2, full_key) in enumerate(possible_keys, 1):
                output += f"{i}. K1={self.int_to_hex(k1, 4)}, K2={self.int_to_hex(k2, 4)}, "
                output += f"完整密钥={self.int_to_hex(full_key, 8)}\n"

                # 验证每个密钥
                valid_count = 0
                for plain, cipher in pairs:
                    test_cipher = self.saes.encrypt(self.saes.encrypt(plain, k1), k2)
                    if test_cipher == cipher:
                        valid_count += 1
                output += f"   验证: {valid_count}/{len(pairs)} 对匹配\n\n"
        else:
            output += "未找到可能的密钥\n"
            output += "注意：为了演示速度，当前只搜索了前256个密钥。\n"
            output += "要搜索完整密钥空间，请修改MeetInTheMiddleAttack类中的循环范围。"

        self.attack_output.setText(output)

    def clear_basic(self):
        """清空基本测试标签页"""
        self.plaintext_edit.clear()
        self.key_edit.clear()
        self.basic_output.clear()

    def clear_ascii(self):
        """清空ASCII标签页"""
        self.ascii_input.clear()
        self.ascii_key.clear()
        self.ascii_output.clear()

    def clear_multi(self):
        """清空多重加密标签页"""
        self.multi_plaintext.clear()
        self.multi_key.clear()
        self.multi_output.clear()

    def clear_cbc(self):
        """清空CBC模式标签页"""
        self.cbc_plaintext.clear()
        self.cbc_key.clear()
        self.cbc_iv.clear()
        self.cbc_output.clear()

    def clear_attack(self):
        """清空攻击标签页"""
        self.attack_plaintext.clear()
        self.attack_ciphertext.clear()
        self.attack_pairs_list.clear()
        self.attack_output.clear()


def main():
    """主函数"""
    app = QApplication(sys.argv)
    window = SAESGUI()
    window.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()