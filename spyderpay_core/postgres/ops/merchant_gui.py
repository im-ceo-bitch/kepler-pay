"""Local Linux desktop POS for pre-license staging, with a real API and QR display.
Tk is optional; OIDC login/token lifecycle is handled by a separate trusted agent.
No payment credential entry, card signing, or offline approval is supported.
"""
import os
import queue
import threading
import uuid
from .merchant_terminal import MerchantAPI, Sales, Terminal, amount_value


def main():
    if os.getenv('SPYDERPAY_ENV') != 'prelicense':
        raise SystemExit('Prelicense only')
    import tkinter as tk
    from tkinter import ttk
    import qrcode
    api = MerchantAPI(os.environ['SPYDERPAY_TERMINAL_ORIGIN'],os.environ['SPYDERPAY_TERMINAL_TOKEN_FILE'],os.environ['SPYDERPAY_TERMINAL_CA_FILE'])
    sales = Sales(os.environ['SPYDERPAY_TERMINAL_STATE_DIR'],api.origin)
    terminal = Terminal(api,sales)
    root = tk.Tk();root.title('SpyderPay POS — PRELICENSE');root.geometry('560x760')
    root.columnconfigure(0,weight=1)
    ttk.Label(root,text='SpyderPay POS',font=('TkDefaultFont',23,'bold')).grid(row=0,pady=(18,4))
    ttk.Label(root,text='Тестовая среда · реальные средства не принимаются').grid(row=1,pady=5)
    account=tk.StringVar();amount=tk.StringVar();sale=tk.StringVar();message=tk.StringVar(value='Загрузите счёт продавца.')
    selector=ttk.Combobox(root,textvariable=account,state='readonly',width=40);selector.grid(row=2,pady=8)
    ttk.Label(root,text='Сумма UZS (целое число)').grid(row=3)
    ttk.Entry(root,textvariable=amount,width=28).grid(row=4,pady=8)
    ttk.Label(root,text='Идентификатор продажи (для восстановления)').grid(row=5)
    ttk.Entry(root,textvariable=sale,width=42).grid(row=6,pady=8)
    buttons=ttk.Frame(root);buttons.grid(row=7,pady=8)
    display=tk.Canvas(root,width=400,height=400,bg='white',highlightthickness=1);display.grid(row=8,pady=8)
    ttk.Label(root,textvariable=message,wraplength=470,justify='center').grid(row=9,pady=8)
    jobs=queue.Queue();busy=False;qr_until=None
    controls=[]
    def clear_qr():
        nonlocal qr_until
        qr_until=None;display.delete('all')
    def run(task,callback):
        nonlocal busy
        if busy:return
        busy=True;clear_qr();message.set('Запрос к серверу…')
        for b in controls:b.configure(state='disabled')
        def worker():
            try:jobs.put((callback,task(),None))
            except Exception as e:jobs.put((callback,None,type(e).__name__))
        threading.Thread(target=worker,daemon=True).start()
    def show_status(result):
        state=result['state'];label={'paid':'Оплачено (тест)','pending':'Ожидает оплаты','unknown':'Неизвестно — восстановите ту же продажу','refunded':'Возвращено','cancelled':'Отменено','expired':'Истёк срок'}.get(state,'Неизвестно')
        message.set(f"{label} · {result.get('amount','—')} UZS · возврат {result.get('refunded_total',0)} UZS · {result.get('sale_id','')}")
    def load_accounts():
        def done(rows):
            selector.configure(values=rows)
            if rows:account.set(rows[0])
            message.set('Выберите счёт продавца.' if rows else 'Нет активных счетов.')
        run(api.accounts,done)
    def create():
        try:
            value=amount_value(int(amount.get()));merchant=account.get()
            if sale.get().strip():
                message.set('Для текущего идентификатора используйте «Восстановить». Очистите поле только для новой продажи.');return
            if sales.pending():
                message.set('Есть неопределённые продажи. Сначала восстановите их.');return
            sid=str(uuid.uuid4());sale.set(sid)
        except (ValueError,OSError):message.set('Проверьте сумму и состояние терминала.');return
        run(lambda:terminal.create(sid,merchant,value),show_status)
    def resume():
        sid=sale.get().strip();run(lambda:terminal.resume(sid),show_status)
    def status():
        sid=sale.get().strip();run(lambda:terminal.status(sid),show_status)
    def pending():
        def done(rows):
            if rows:sale.set(rows[0]['id']);message.set(f'Неопределённых продаж: {len(rows)}. Восстановите выбранную.')
            else:message.set('Неопределённых продаж нет.')
        run(sales.pending,done)
    def qr():
        sid=sale.get().strip()
        def task():
            import jwt,time
            token=terminal.qr(sid)
            # Expiry is only a display limit. Wallet independently verifies the signature.
            claims=jwt.decode(token,options={'verify_signature':False})
            remaining=claims.get('exp',0)-time.time()
            if not 0<remaining<=90:raise ValueError('invalid_qr_expiry')
            code=qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M,border=4);code.add_data(token);code.make(fit=True)
            return code.get_matrix(),time.monotonic()+remaining,sid
        def done(result):
            import time
            nonlocal qr_until
            matrix,deadline,sid=result
            if deadline<=time.monotonic() or sale.get().strip()!=sid:return
            pixels=400//len(matrix);offset=(400-pixels*len(matrix))//2
            if pixels<2:message.set('QR слишком велик.');return
            for y,row in enumerate(matrix):
                for x,black in enumerate(row):
                    if black:display.create_rectangle(offset+x*pixels,offset+y*pixels,offset+(x+1)*pixels,offset+(y+1)*pixels,fill='black',outline='')
            qr_until=deadline;message.set('Подписанный QR · после оплаты нажмите «Статус».')
        run(task,done)
    for label,action in [('Счета',load_accounts),('Создать',create),('Восстановить',resume),('Статус',status),('QR',qr),('Неизвестные',pending)]:
        b=ttk.Button(buttons,text=label,command=action);b.pack(side='left',padx=1);controls.append(b)
    def tick():
        import time
        nonlocal busy
        if qr_until is not None and time.monotonic()>=qr_until:clear_qr();message.set('QR истёк. Запросите новый.')
        try:callback,result,error=jobs.get_nowait()
        except queue.Empty:pass
        else:
            busy=False
            for b in controls:b.configure(state='normal')
            if error:message.set('Запрос не подтверждён. Не создавайте дубликат. Восстановите ту же продажу.')
            else:callback(result)
        root.after(150,tick)
    sale.trace_add('write',lambda *_:clear_qr())
    root.after(150,tick);root.mainloop()

if __name__=='__main__':main()
