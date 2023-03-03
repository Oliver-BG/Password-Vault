# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'deleteAccount.ui'
#
# Created by: PyQt5 UI code generator 5.15.4
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_DeleteAccount(object):
    def setupUi(self, DeleteAccount):
        DeleteAccount.setObjectName("DeleteAccount")
        DeleteAccount.resize(596, 744)
        DeleteAccount.setContextMenuPolicy(QtCore.Qt.DefaultContextMenu)
        DeleteAccount.setStyleSheet("background-color:#003EBB;")
        self.label_title = QtWidgets.QLabel(DeleteAccount)
        self.label_title.setGeometry(QtCore.QRect(0, 290, 591, 41))
        self.label_title.setStyleSheet("qproperty-alignment:AlignCenter;\n"
"font-size: 24px;\n"
"color: yellow;\n"
"")
        self.label_title.setObjectName("label_title")
        self.btn_back = QtWidgets.QPushButton(DeleteAccount)
        self.btn_back.setGeometry(QtCore.QRect(100, 600, 161, 51))
        self.btn_back.setStyleSheet("QPushButton{\n"
"    font-size : 15px;\n"
"    background-color : \"#F87E2E\";\n"
"    color: \"white\";\n"
"    font-weight: bold;\n"
"    border-radius: 4px;\n"
"}\n"
"\n"
"QPushButton:hover{\n"
"    background-color : \"#FFD139\";\n"
"}")
        self.btn_back.setObjectName("btn_back")
        self.btn_del_acc = QtWidgets.QPushButton(DeleteAccount)
        self.btn_del_acc.setGeometry(QtCore.QRect(330, 600, 161, 51))
        self.btn_del_acc.setStyleSheet("QPushButton{\n"
"    font-size : 15px;\n"
"    background-color : \"#F87E2E\";\n"
"    color: \"white\";\n"
"    font-weight: bold;\n"
"    border-radius: 4px;\n"
"}\n"
"\n"
"QPushButton:hover{\n"
"    background-color : \"#FFD139\";\n"
"}")
        self.btn_del_acc.setObjectName("btn_del_acc")
        self.label_user_acc = QtWidgets.QLabel(DeleteAccount)
        self.label_user_acc.setGeometry(QtCore.QRect(0, 340, 591, 21))
        self.label_user_acc.setStyleSheet("qproperty-alignment:AlignCenter;\n"
"font-size: 15px;\n"
"color: white;\n"
"")
        self.label_user_acc.setObjectName("label_user_acc")
        self.txt_pass = QtWidgets.QLineEdit(DeleteAccount)
        self.txt_pass.setGeometry(QtCore.QRect(150, 390, 341, 31))
        self.txt_pass.setStyleSheet("border-radius : 5px;\n"
"font-family: \"sans-serif\";\n"
"height : 34px;\n"
"font-weight: 1;\n"
"background-color : \"#FFFFFF\";\n"
"border : 1px solid;\n"
"font-size: 18px;")
        self.txt_pass.setEchoMode(QtWidgets.QLineEdit.Password)
        self.txt_pass.setObjectName("txt_pass")
        self.icon_confirm = QtWidgets.QLabel(DeleteAccount)
        self.icon_confirm.setGeometry(QtCore.QRect(100, 440, 41, 41))
        self.icon_confirm.setText("")
        self.icon_confirm.setPixmap(QtGui.QPixmap("images/confirm icon.png"))
        self.icon_confirm.setScaledContents(True)
        self.icon_confirm.setObjectName("icon_confirm")
        self.txt_confirm = QtWidgets.QLineEdit(DeleteAccount)
        self.txt_confirm.setGeometry(QtCore.QRect(150, 450, 341, 31))
        self.txt_confirm.setStyleSheet("border-radius : 5px;\n"
"font-family: \"sans-serif\";\n"
"height : 34px;\n"
"background-color : \"#FFFFFF\";\n"
"border : 1px solid;\n"
"font-size: 18px;")
        self.txt_confirm.setEchoMode(QtWidgets.QLineEdit.Password)
        self.txt_confirm.setObjectName("txt_confirm")
        self.label_pass_icon = QtWidgets.QLabel(DeleteAccount)
        self.label_pass_icon.setGeometry(QtCore.QRect(100, 380, 41, 51))
        self.label_pass_icon.setText("")
        self.label_pass_icon.setPixmap(QtGui.QPixmap("images/pass_icon.png"))
        self.label_pass_icon.setScaledContents(True)
        self.label_pass_icon.setObjectName("label_pass_icon")
        self.image_main = QtWidgets.QLabel(DeleteAccount)
        self.image_main.setGeometry(QtCore.QRect(150, 20, 301, 251))
        self.image_main.setText("")
        self.image_main.setPixmap(QtGui.QPixmap("images/main_image.png"))
        self.image_main.setScaledContents(True)
        self.image_main.setObjectName("image_main")
        self.label_error = QtWidgets.QLabel(DeleteAccount)
        self.label_error.setGeometry(QtCore.QRect(110, 510, 391, 51))
        self.label_error.setStyleSheet("font-size: 15px;\n"
"color: \"#50FF00\";\n"
"qproperty-alignment: AlignCenter;\n"
"font-weight: bold;\n"
"\n"
"")
        self.label_error.setWordWrap(True)
        self.label_error.setObjectName("label_error")

        self.retranslateUi(DeleteAccount)
        QtCore.QMetaObject.connectSlotsByName(DeleteAccount)

    def retranslateUi(self, DeleteAccount):
        _translate = QtCore.QCoreApplication.translate
        DeleteAccount.setWindowTitle(_translate("DeleteAccount", "Dialog"))
        self.label_title.setText(_translate("DeleteAccount", "D E L E T E     A C C O U N T"))
        self.btn_back.setText(_translate("DeleteAccount", "<< BACK"))
        self.btn_del_acc.setText(_translate("DeleteAccount", "Delete Account"))
        self.label_user_acc.setText(_translate("DeleteAccount", "Account: <User>"))
        self.txt_pass.setPlaceholderText(_translate("DeleteAccount", " P a s s w o r d"))
        self.txt_confirm.setPlaceholderText(_translate("DeleteAccount", " C o n f i r m     P a s s w o r d"))
        self.label_error.setText(_translate("DeleteAccount", "Please type your password again to confirm"))


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    DeleteAccount = QtWidgets.QDialog()
    ui = Ui_DeleteAccount()
    ui.setupUi(DeleteAccount)
    DeleteAccount.show()
    sys.exit(app.exec_())
