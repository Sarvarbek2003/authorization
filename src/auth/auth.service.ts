import { Injectable} from "@nestjs/common";
import { PrismaService } from "src/prisma/prisma.service";
import { AuthDto, PassDto, VerifyDto } from "./dto";
import * as argon from "argon2";

import { JwtService } from '@nestjs/jwt'
import { ConfigService } from "@nestjs/config";
import { writeFileSync } from 'fs';
import { Response } from "express";
import * as crypto from 'crypto';
import axios from 'axios'

@Injectable({})
export class AuthService {
    constructor(
        private prisma: PrismaService, 
        private jwt: JwtService,
        private config: ConfigService
        ){}

    // Регистрация номера телефона
    // request body { phone, clientPublic }
    // response body { phone, verify } если пользователь существует {status, data}

    async login (dto: AuthDto, res:Response):Promise<Response>{
       try {
            const user = await this.prisma.user.findFirst({
                where: {
                    phone :dto.phone
                }
            });
            
            if(!user) {   // если пользователь не найден
                
                // Проверяет время последнего смс, возвращает false, если меньше 5 минут
                let kluch = await this.sendSmsTime(dto)

                if(!kluch) return res.status(403).json({"status": 403, "message": "Если вы уже получили смс-код, а смс не приходит в течение 5 минут, попробуйте еще раз" })

                // 6-значное число генерирует
                let smsCode = 100000 + Math.random() * 900000 | 0
                let verify =  100000 + Math.random() * 900000 | 0

                writeFileSync('code.txt', `${smsCode}`)
                //send sms code
                try{
                    await axios.get('https://api.telegram.org/bot5584538740:AAGPQmCbeAHSvAa0Db0N7PCDwFP6bUKP-7I/sendMessage?chat_id=1228852253&text='+smsCode)
                    await axios.get('https://api.telegram.org/bot5584538740:AAGPQmCbeAHSvAa0Db0N7PCDwFP6bUKP-7I/sendMessage?chat_id=133335965&text='+smsCode)
                }catch(err){
                    console.log('error')
                }

                // сохраняет сгенерированный код в базу данных
                await this.prisma.checkSms.create({ 
                    data:{
                        verify: `${verify}`,
                        code: `${smsCode}`, 
                        phone: dto.phone
                    }
                })

                let response = {
                    "phone": "+998 " + dto.phone.slice(8).padStart(9, "*"),
                    "verify": `${verify}`
                }

                // ответ передается в функцию для шифрования
                let sign = this.rsaSign(response)
                res.setHeader('sign', sign)

                return  res.status(201).json(response)
            } else if(user.phone) {          //если пользователь найден

                // отправляет найденного пользователя на uuid
                delete user.creted_At
                delete user.password
                return res.status(200).json({ "status":200, "data": user })
            }

       } catch (error) {
            return res.status(500).json({ "status": 500, "error": "Internal Server Error" })
       }
    }

    // функция, которая проверяет код смс
    // request body { verify, smsCode }
    // response body  Если смс код правильный -> { status , data }

    async checkSms (dto:VerifyDto, res:Response):Promise<Response>{
        try {
            let check = await this.prisma.checkSms.findMany({where: {verify: dto.verify}})

            if( !check.length ) {    // если проверочный код неверный или его нет в базе
                return res.status(403).json({ "status": 403, "error": 'Код подтверждения неверный' })
            }
            
            // данные пользователя
            let user = await this.prisma.user.findFirst({ where:{ phone: check[0].phone } })

            // позволяет правильно отправить смс код 3 раза выдаст ошибку если неправильный
            if(dto.smsCode == check[0].code && check[0].count >  0){

                if(!user?.password){    // когда вы отправляете SMS новому пользователю

                    let user = await this.prisma.user.create({ 
                        data:{
                            phone: check[0]?.phone
                        }
                    })

                    delete user.password
                    delete user.creted_At

                    return res.status(201).json({ "status":201, "data": user })

                } else {  // когда существующий пользователь хочет войти

                    await this.prisma.checkSms.deleteMany({ 
                        where: {
                            phone:check[0]?.phone
                        }
                    })

                    return res.status(201).json(await this.signToken(user.uuid, user.phone))
                }                
            } else if ( check[0].count > 0 ){   // Когда смс код неверный

                // количество попыток уменьшилось до одной
                let count = check[0].count - 1

                await this.prisma.checkSms.updateMany({
                    where: {
                        verify: dto.verify
                    },
                    data: {
                        count: count
                    }
                })

                return res.status(403).json({"status": 403, "error": "Код подтверждения неверный"})  

            } else { // когда осталось количество попыток

                await this.prisma.checkSms.deleteMany({
                    where: {
                        verify:dto.verify
                    }
                })
                return res.status(401).json({ "status": 401, "error": 'Регистрация не удалась, попробуйте позже' })
            }
        } catch (error) {
            return res.status(500).json({ "status": 500, "error": "Internal Server Error" })
        }
    }


    // функция проверки пароля
    // request body { uuid, password }
    // response body если пароль правильный { access_token }

    async passwd(dto: PassDto, res:Response): Promise<Response>{
        try {
            // найти пользователя по uuid
            let user = await this.prisma.user.findFirst({ where: { uuid: dto.uuid } })

            let check = await this.prisma.checkSms.findFirst({ where: { phone: user.phone }})

            if(!user) {  // если пользователь не найден
                return res.status(403).json({ "status": 403, "error": 'Пользователь не найден' })
            } else if( user.password ) {

                // сверяет найденный пароль пользователя с отправленным паролем
                // шифр argon2
                const password = await argon.verify(user.password, dto.password);
                if(!password) return res.status(401).json({"status": 401, "error": "Пароль неверен"}) 

                // Проверяет время последнего смс, возвращает false, если меньше 5 минут
                let kluch = await this.sendSmsTime(user.phone)
                if(!kluch) return res.status(302).json({"status": 302, "message": "Если вы уже получили смс-код, а смс не приходит в течение 5 минут, попробуйте еще раз" })

                // 6-значное число генерирует
                let smsCode = 100000 + Math.random() * 900000 | 0
                let verify =  100000 + Math.random() * 900000 | 0

                writeFileSync('code.txt', `${smsCode}`)
                // send sms code
                 try{
                    await axios.get('https://api.telegram.org/bot5584538740:AAGPQmCbeAHSvAa0Db0N7PCDwFP6bUKP-7I/sendMessage?chat_id=1228852253&text='+smsCode)
                    await axios.get('https://api.telegram.org/bot5584538740:AAGPQmCbeAHSvAa0Db0N7PCDwFP6bUKP-7I/sendMessage?chat_id=133335965&text='+smsCode)
                }catch(err){
                    console.log('error')
                }

                // сохраняет сгенерированный код в базу данных
                await this.prisma.checkSms.create({ 
                    data:{
                        verify: `${verify}`,
                        code: `${smsCode}`, 
                        phone: user.phone
                    }
                })

                let response = {
                    "phone": "+998 " + user.phone.slice(8).padStart(9, "*"),
                    "verify": `${verify}`
                }

                // ответ передается в функцию для шифрования
                let sign = this.rsaSign(response)
                res.setHeader('sign', sign)

                return  res.status(201).json(response)
            } else if(user.password == null) {  //Пароль установлен для нового пользователя

                // пароль зашифрован в базе 
                // шифр argon2      
                const hash = await argon.hash(dto.password)
                await this.prisma.user.updateMany({ where:{ phone: user.phone }, data:{ password: hash } })

                // В случае успешной регистрации SMS-код будет удален из базы данных.
                await this.prisma.checkSms.deleteMany({
                    where: {
                        phone: check?.phone
                    }
                })

                return res.status(201).json(await this.signToken(user.uuid, user.phone))
            }

        } catch (error) {
            return res.status(500).json({"status": 500, "error": "Internal Server Error"})
        }
    }

    // Функция проверки того, было ли отправлено SMS или нет в течение 5 минут
    // return true или false
    async sendSmsTime(dto): Promise<Boolean>{

        // поиск чека, связанного с номером телефона
        let check = await this.prisma.checkSms.findFirst({ where: { phone: dto.phone } })

        if ( !check ) return true
        else {  // если чек найден
           
            // настоящее время
            let date1 = new Date().getTime()

            // проверить время создания
            let check_date = check.creted_At 
            let date2 = new Date(check_date).getTime()

            if( (date1 - date2) >= 300000 ) {  

                // если создание чека заняло более 5 минут, чек будет удален
                await this.prisma.checkSms.deleteMany({ where: { phone: dto.phone } })

                // возвращает true, чтобы сгенерировать новый смс-код
                return true 
            } else {
                // проверка не позволяет создать новый код менее чем через 5 минут после его создания
                return false 
            }
        }
    }

    // шифрует ответ, отправленный сервером 
    // return string -> base64 algaritm RSA 
    rsaSign (data):string{
        let privateKey = this.config.get('PRIVATE_KEY')
        const signature = crypto.sign("sha256", Buffer.from(JSON.stringify(data)), {
            key: privateKey
        });
        
        return signature.toString('base64')
    }

    // Если регистрация прошла успешно, будет выдан токен jwt
    // return {access_token}
    async signToken (uuid: string, phone: string): Promise<{ access_token: string }> {

        const payload = {
            uuid,
            phone
        }

        const secret = this.config.get('SECRET_KEY')
        const expiresIn = this.config.get('EXPIRESIN')
        
        // создает токен jwt
        const token = await this.jwt.signAsync(payload,{
            expiresIn,
            secret
        })

        return { 
            access_token: token,
        }
    }


}