package org.pgpchat; /** NIS Assignment: Debugging Class
 * @author Claudia Greenberg (GRNCLA009), Jane Imrie (IMRJAN001), Josie Rey (RYXJOS002), Lehasa Seoe (SXXLEH001)
 * @version 1.0
 * @since May 2022
 */

import javax.swing.JTextArea;

public class Logger {

    int mode;
    private static final int DEBUG = 1;

    /**
     * Constructor
     * @param m
     */
    public Logger(int m) {
        this.mode = m;
    }

    /**
     * Print to terminal
     */
    public void dbg(String msg) {
        if (mode == DEBUG) {
            System.out.println("" + msg);
        }
    }

    /**
     * Print to terminal
     * @param msg
     * @param a number of iterations
     */
    public void dbg (String msg, int a) {
        if (mode == DEBUG) {
            for (int i = 0; i < a; i++) {
                System.out.print("  ");
            }
            System.out.println("> " + msg);
        }
    }

    /**
     * Append to group chat messages
     * @param groupChatArea
     * @param messages
     * @param msg
     * @return appended group chat messages
     */
    public String log(JTextArea groupChatArea, String messages, String msg){
        if(messages == null){
            messages = "";
        }
        messages += "\n~ " + msg;
        groupChatArea.setText(messages); 
        return messages;
    }

    /**
     * Print to screen
     * @param msg
     */
    public void print (String msg) {
        System.out.println("~ " + msg);
    }

    /**
     * Append to group chat messages
     * @param groupChatArea
     * @param messages
     * @param user
     * @param msg
     * @return appended group chat messages
     */
    public String prompt (JTextArea groupChatArea, String messages, String user, String msg) {
        if(messages == null){
            messages = "";
        }
        messages += "\n" + user + ": " + msg;
        groupChatArea.setText(messages); 
        return messages;
    } 

    /**
     * Show input
     * @param c character
     */
    public void showInput(char c) {
        System.out.print(c);
    }
}
