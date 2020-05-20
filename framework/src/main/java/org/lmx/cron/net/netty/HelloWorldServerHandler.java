package org.lmx.cron.net.netty;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.SimpleChannelInboundHandler;
import lombok.extern.slf4j.Slf4j;

/**
 * 功能描述：HelloWorld
 *
 * @program: block-chain-j
 * @author: LM.X
 * @create: 2020-04-07 11:39
 **/
@Slf4j
public class HelloWorldServerHandler extends SimpleChannelInboundHandler {
    @Override
    protected void channelRead0(ChannelHandlerContext ctx, Object msg) throws Exception {

    }

    /**
     * 功能描述: 表示Server处于活动状态，建立连接时调用
     *
     * @param ctx 通道上下文对象
     * @return void
     * @author LM.X
     * @date 2020/4/7 11:53
     */
    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
        log.info("Server端状态：存活……");
    }

    /**
     * 功能描述: 接收到消息时调用
     *
     * @param ctx 通道上下文
     * @param msg 消息内容
     * @return void
     * @author LM.X
     * @date 2020/4/7 11:55
     */
    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        final String data = String.format("Server端 收到消息：%s", msg);

        ctx.write(data);
        ctx.flush();

        log.info(data);
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        ctx.close();

        log.info("Netty异常：{}", cause);
    }
}
